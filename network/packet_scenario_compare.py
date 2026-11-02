"""TShark의 필드만 대조한다. PCAP 디코더나 AWS 원인 판정기는 구현하지 않는다."""

from __future__ import annotations

import csv
import io
from decimal import Decimal

from sg_connection_timeline import epoch, integer
from waf_packet_timeline import FIELDS, MAX_BYTES, analyze_csv

EXTRA_FIELDS = (
    "frame.number",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.len",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "http.request.method",
    "http.response.code",
)
ALL_FIELDS = FIELDS + EXTRA_FIELDS


def compare(raw, worker, config):
    """관측 부재를 원인으로 승격하지 않고 설정·클라이언트·패킷을 함께 검증한다.

    Constraints: 1MiB/256행, 신규 연결 1개, 합성 GET 한 건, 원본 seq/ack 32비트.
    Side-effects: 입력은 변경하지 않는다. 잘못된 입력은 예외, 기대 불일치는 failed이다.
    """
    if len(raw.encode()) > MAX_BYTES:
        raise ValueError("CSV 용량 초과")
    reader = csv.DictReader(io.StringIO(raw))
    if tuple(reader.fieldnames or ()) != ALL_FIELDS:
        raise ValueError("TShark 필드 오류")
    rows = []
    normalized_booleans = 0
    for row in reader:
        if len(rows) >= 256 or None in row or any(v is None for v in row.values()):
            raise ValueError("패킷 행 상한/형식 오류")
        # TShark 버전에 따라 FT_BOOLEAN이 True/False로 출력된다. 원본 CSV는 보존하고
        # 기존 TCP 검증기에 전달하는 사본만 정확한 두 표기에 한해 정규화한다.
        for key in FIELDS[6:] + EXTRA_FIELDS[4:7]:
            if row[key] in ("True", "False"):
                row[key] = {"True": "1", "False": "0"}[row[key]]
                normalized_booleans += 1
        for key in EXTRA_FIELDS[:4]:
            # raw seq/ack는 10자리까지 필요하므로 기존 9자리 정수 파서를 확장하지 않는다.
            value = row[key]
            if not value.isascii() or not value.isdigit() or len(value) > 10:
                raise ValueError("프레임/seq/ack 형식 오류")
            if int(value) > (2**32 - 1):
                raise ValueError("seq/ack 범위 오류")
        for key in EXTRA_FIELDS[4:7]:
            if row[key] not in ("", "0", "1"):
                raise ValueError("재전송 필드 오류")
        if row["http.request.method"] not in ("", "GET"):
            raise ValueError("합성 GET 이외 요청")
        if row["http.response.code"] not in ("", "200", "403"):
            raise ValueError("HTTP 상태 오류")
        rows.append(row)
    capture = worker["capture"]
    span = epoch(capture["ended_epoch"]) - epoch(capture["started_epoch"])
    if not 0 < span <= 13:
        raise ValueError("캡처 시간 상한 오류")
    if (
        config.get("requests") != 1
        or config.get("concurrency") != 1
        or config.get("capture_seconds") != 8
        or config.get("packets") != 256
        or config.get("file_bytes") != MAX_BYTES
    ):
        raise ValueError("실험 상한 설정 오류")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows({key: row[key] for key in FIELDS} for row in rows)
    tcp = analyze_csv(output.getvalue(), start=capture["started_epoch"], end=capture["ended_epoch"])
    target, client, port = config["target"], config["client"], str(config["port"])
    if config["scenario"] not in ("normal", "drop", "rst", "http403") or port != "8080":
        raise ValueError("시나리오/포트 오류")
    if worker["run_id"] != config["run_id"] or worker["scenario"] != config["scenario"]:
        raise ValueError("다른 실행의 증거 혼합")
    frames = [int(row["frame.number"]) for row in rows]
    if any(a >= b for a, b in zip(frames, frames[1:], strict=False)):
        raise ValueError("프레임 중복/역순")
    for row in rows:
        if int(row["frame.number"]) < 1 or int(row["tcp.len"]) > 65535:
            raise ValueError("프레임/세그먼트 길이 범위 오류")
        outgoing = row["ip.src"] == client and row["ip.dst"] == target
        incoming = row["ip.src"] == target and row["ip.dst"] == client
        if not (
            (outgoing and row["tcp.dstport"] == port) or (incoming and row["tcp.srcport"] == port)
        ):
            raise ValueError("소유 연결 이외 패킷")
        row["direction"] = "client_to_server" if outgoing else "server_to_client"
    syns = [
        r
        for r in rows
        if r["direction"] == "client_to_server"
        and r["tcp.flags.syn"] == "1"
        and r["tcp.flags.ack"] == "0"
    ]
    first = syns[0] if syns else None
    synacks = [
        r
        for r in rows
        if first
        and r["direction"] == "server_to_client"
        and r["tcp.flags.syn"] == "1"
        and r["tcp.flags.ack"] == "1"
        and int(r["tcp.ack_raw"]) == (int(first["tcp.seq_raw"]) + 1) % 2**32
    ]
    synack = synacks[0] if synacks else None
    acks = [
        r
        for r in rows
        if synack
        and r["direction"] == "client_to_server"
        and r["tcp.flags.ack"] == "1"
        and r["tcp.flags.syn"] == "0"
        and r["tcp.flags.reset"] == "0"
        and int(r["frame.number"]) > int(synack["frame.number"])
        and int(r["tcp.seq_raw"]) == (int(first["tcp.seq_raw"]) + 1) % 2**32
        and int(r["tcp.ack_raw"]) == (int(synack["tcp.seq_raw"]) + 1) % 2**32
    ]
    handshake = bool(
        first and synack and acks and int(first["frame.number"]) < int(synack["frame.number"])
    )
    resets = [r for r in rows if r["tcp.flags.reset"] == "1"]
    fins = [r for r in rows if r["tcp.flags.fin"] == "1"]
    statuses = [int(r["http.response.code"]) for r in rows if r["http.response.code"]]
    requests = [r for r in rows if r["http.request.method"]]
    syn_retrans = [
        r
        for r in syns[1:]
        if first
        and r["tcp.seq_raw"] == first["tcp.seq_raw"]
        and r["tcp.stream"] == first["tcp.stream"]
        and r["tcp.srcport"] == first["tcp.srcport"]
    ]
    retrans = [
        r for r in rows if any(r[key] == "1" for key in EXTRA_FIELDS[4:7]) or r in syn_retrans
    ]
    observed = worker.get("client") or {}
    reasons = []
    if not worker.get("worker_complete") or worker.get("error"):
        reasons.append("acquisition_failed")
    if capture.get("exit") != 124 or capture.get("kernel_dropped") != 0:
        reasons.append("capture_incomplete")
    if capture.get("packets") != len(rows) or not 0 < len(rows) < 256:
        reasons.append("capture_count_mismatch")
    if len(tcp["streams"]) != 1 or not first or len(syns) != 1 + len(syn_retrans):
        reasons.append("expected_one_new_connection")
    if any(entry["input_out_of_order"] for entry in tcp["streams"].values()):
        reasons.append("packet_clock_out_of_order")
    if first and observed.get("local_port", 0) not in (0, int(first["tcp.srcport"])):
        reasons.append("client_socket_mismatch")
    mode = config["scenario"]
    if mode in ("normal", "http403"):
        expected = 200 if mode == "normal" else 403
        responses = [r for r in rows if r["http.response.code"]]
        if (
            not handshake
            or statuses != [expected]
            or len(requests) != 1
            or requests[0]["direction"] != "client_to_server"
            or observed.get("exit") != 0
            or observed.get("http_status") != expected
            or responses[0]["direction"] != "server_to_client"
            or int(requests[0]["frame.number"]) < int(acks[0]["frame.number"])
            or int(responses[0]["frame.number"]) <= int(requests[0]["frame.number"])
        ):
            reasons.append("http_expectation_mismatch")
    elif mode == "drop":
        if (
            not first
            or any(r["direction"] == "server_to_client" for r in rows)
            or handshake
            or statuses
            or requests
            or observed.get("exit") != 28
            or observed.get("reason") != "timeout"
            or observed.get("http_status") != 0
        ):
            reasons.append("drop_expectation_mismatch")
    else:
        valid_rst = [
            r
            for r in resets
            if first
            and r["direction"] == "server_to_client"
            and r["tcp.flags.ack"] == "1"
            and int(r["tcp.ack_raw"]) == (int(first["tcp.seq_raw"]) + 1) % 2**32
            and int(r["frame.number"]) > int(first["frame.number"])
        ]
        if (
            not valid_rst
            or handshake
            or statuses
            or requests
            or observed.get("exit") != 7
            or observed.get("http_status") != 0
        ):
            reasons.append("rst_expectation_mismatch")
    if mode in ("drop", "rst") and not config.get("rule_verified"):
        reasons.append("firewall_rule_unverified")
    if mode in ("drop", "rst") and integer(str(config.get("rule_packets", 0)), 0, 999999999) < 1:
        reasons.append("firewall_rule_not_hit")

    def event(row):
        return {
            "frame": int(row["frame.number"]),
            "epoch": row["frame.time_epoch"],
            "direction": row["direction"],
            "seq_raw": row["tcp.seq_raw"],
            "ack_raw": row["tcp.ack_raw"],
        }

    response = synack or next((r for r in resets if r["direction"] == "server_to_client"), None)
    return {
        "scenario": mode,
        "normalized_boolean_fields": normalized_booleans,
        "run_id": config["run_id"],
        "passed": not reasons,
        "reasons": reasons,
        "tcp": tcp,
        "packet_count": len(rows),
        "new_connections": len(tcp["streams"]),
        "handshake_verified": handshake,
        "handshake_frames": [event(r) for r in (first, synack, acks[0] if acks else None) if r],
        "fin": [event(r) for r in fins],
        "rst": [event(r) for r in resets],
        "http_statuses": statuses,
        "syn_retransmissions": len(syn_retrans),
        "retransmissions": len(retrans),
        "retransmission_frames": [int(r["frame.number"]) for r in retrans],
        "response_seconds": str(
            epoch(response["frame.time_epoch"]) - epoch(first["frame.time_epoch"])
        )
        if response and first
        else None,
        "observation_seconds": str(
            Decimal(capture["ended_epoch"]) - Decimal(capture["started_epoch"])
        ),
        "limitations": (
            "재전송 0은 관측 구간의 값이다. 클라이언트 4초 연결 timeout과 8초 캡처로 "
            "이후 재전송은 미관측일 수 있다. AWS 원인·전파·SLA 근거가 아니다."
        ),
    }
