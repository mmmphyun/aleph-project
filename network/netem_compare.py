"""TShark 필드·재조립 출력과 앱/qdisc 증거를 대조한다. PCAP/TCP 재조립은 하지 않는다.

Why: 설정 성공·TCP ACK·앱 본문 완료 및 순서 역전 후보를 서로 다른 근거로 남긴다.
Constraints: 입력별 1MiB, 캡처별 1024행, 단일 IPv4 연결, 합성 응답 본문 64KiB.
Side-effects: 순수 오프라인 분석. 모순·상한·불완전 캡처는 예외로 전파한다.
"""

from __future__ import annotations

import collections
import csv
import hashlib
import io
import json
import re
from decimal import Decimal

from connection_compare import handshake, hex_bytes, number
from netem_worker import BODY, BODY_SHA256, PROFILE, SCENARIOS, request, response_head, verify_qdisc
from sg_connection_timeline import epoch
from waf_packet_timeline import FIELDS, MAX_BYTES, analyze_csv

EXTRA_FIELDS = (
    "frame.number",
    "frame.len",
    "frame.cap_len",
    "ip.id",
    "ip.hdr_len",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.len",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.acks_frame",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.payload",
)
ALL_FIELDS = FIELDS + EXTRA_FIELDS
MOD = 2**32


def parse_fields(raw, config, capture, prefix, client_port):
    if not isinstance(raw, str) or len(raw.encode()) > MAX_BYTES:
        raise ValueError("필드 파일 1MiB 상한/형식")
    if not capture.get("valid") or capture.get("kernel_dropped") != 0 or capture.get("errors"):
        raise ValueError("불완전 캡처: 장애 효과로 판정 금지")
    expected_peer = config["client"] if prefix == "s" else config["server"]
    if (
        capture.get("interface") != {"s": "eth0", "p": "eth0", "q": "ifb0"}[prefix]
        or capture.get("peer") != expected_peer
    ):
        raise ValueError("실제 캡처 위치/대상 불일치")
    lower, upper = epoch(capture["started_epoch"]), epoch(capture["ended_epoch"])
    if not 0 < upper - lower <= 24 or capture.get("exit") != 124:
        raise ValueError("캡처 시간/종료 사유 불일치")
    reader = csv.DictReader(io.StringIO(raw))
    if tuple(reader.fieldnames or ()) != ALL_FIELDS:
        raise ValueError("TShark 필드 규격 불일치")
    rows, streams = [], set()
    for row in reader:
        if len(rows) >= 1024 or None in row or any(v is None for v in row.values()):
            raise ValueError("패킷 행 상한/필드 수 불일치")
        for key in FIELDS[6:] + EXTRA_FIELDS[10:15]:
            row[key] = {"True": "1", "False": "0", "": "0"}.get(row[key], row[key])
            if row[key] not in ("0", "1"):
                raise ValueError("TCP 플래그/분석 표기 오류")
        for key in (
            "frame.number",
            "frame.len",
            "frame.cap_len",
            "ip.hdr_len",
            "tcp.seq_raw",
            "tcp.ack_raw",
            "tcp.len",
        ):
            row[key] = number(row[key])
        if row["frame.cap_len"] != row["frame.len"] or not 0 < row["frame.len"] <= 65599:
            raise ValueError("프레임 절단/길이 오류")
        if row["ip.hdr_len"] != 20 or row["tcp.len"] > 65535:
            raise ValueError("합성 IPv4 헤더/세그먼트 규격 오류")
        if not re.fullmatch(r"0x[0-9a-fA-F]{4}", row["ip.id"]):
            raise ValueError("IPv4 패킷 ID 오류")
        if not row["frame.number"] or (rows and row["frame.number"] <= rows[-1]["frame.number"]):
            raise ValueError("프레임 번호 중복/역순")
        timestamp = epoch(row["frame.time_epoch"])
        if not lower <= timestamp <= upper or (rows and timestamp < rows[-1]["time"]):
            raise ValueError("패킷 시각 범위/역순")
        row["time"] = timestamp
        row["payload"] = hex_bytes(row["tcp.payload"].replace(":", ""))
        if len(row["payload"]) != row["tcp.len"]:
            raise ValueError("디코딩된 TCP 길이/페이로드 불일치")
        outgoing = (row["ip.src"], row["tcp.srcport"], row["ip.dst"], row["tcp.dstport"]) == (
            config["client"],
            str(client_port),
            config["server"],
            "8080",
        )
        incoming = (row["ip.src"], row["tcp.srcport"], row["ip.dst"], row["tcp.dstport"]) == (
            config["server"],
            "8080",
            config["client"],
            str(client_port),
        )
        if not (outgoing or incoming) or (prefix == "q" and not incoming):
            raise ValueError("소유 연결/캡처 위치 이외 패킷")
        row["direction"] = "client_to_server" if outgoing else "server_to_client"
        number(row["tcp.stream"], 999999999)
        streams.add(row["tcp.stream"])
        rows.append(row)
    if len(streams) != 1 or len(rows) != capture.get("packets") or not 0 < len(rows) < 1024:
        raise ValueError("캡처 개수/단일 연결/패킷 상한 불일치")
    normalized = io.StringIO()
    writer = csv.DictWriter(normalized, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows({k: row[k] for k in FIELDS} for row in rows)
    analyze_csv(normalized.getvalue(), start=capture["started_epoch"], end=capture["ended_epoch"])
    return rows


def parse_follow(raw, config, client_port):
    """TShark가 이미 재조립한 raw follow 출력의 방향별 바이트만 읽는다."""
    if not isinstance(raw, str) or len(raw.encode()) > MAX_BYTES:
        raise ValueError("재조립 출력 상한")
    nodes, values, active = {}, [bytearray(), bytearray()], False
    lines = [line for line in raw.splitlines() if line]
    if len(lines) < 7 or any(set(lines[i]) != {"="} or len(lines[i]) < 20 for i in (0, -1)):
        raise ValueError("불완전 재조립 출력 경계")
    if lines[1] != "Follow: tcp,raw" or not re.fullmatch(r"Filter: tcp.stream eq [0-9]+", lines[2]):
        raise ValueError("재조립 헤더 규격")
    for line in lines[3:-1]:
        if not line or set(line) == {"="}:
            continue
        if line.startswith(("Follow: tcp,raw", "Filter: tcp.stream eq ")):
            if active:
                raise ValueError("중복 재조립 헤더")
            continue
        match = re.fullmatch(r"Node ([01]): (\d+\.\d+\.\d+\.\d+):(\d+)", line)
        if match:
            index = int(match[1])
            if index in nodes or active:
                raise ValueError("재조립 노드 중복/역순")
            nodes[index] = (match[2], int(match[3]))
            continue
        if len(nodes) != 2:
            raise ValueError("재조립 헤더 누락/불명확 출력")
        active = True
        index = 1 if line.startswith("\t") else 0
        data = hex_bytes(line[1:] if index else line, 67584)
        values[index].extend(data)
        if sum(map(len, values)) > 69632:
            raise ValueError("합성 스트림 재조립 바이트 상한")
    expected = {(config["client"], client_port), (config["server"], 8080)}
    if set(nodes.values()) != expected or not active:
        raise ValueError("재조립 주소/포트/데이터 누락")
    return {
        "client" if nodes[i] == (config["client"], client_port) else "server": bytes(values[i])
        for i in (0, 1)
    }


def packet_key(row):
    return (
        row["tcp.seq_raw"],
        row["tcp.ack_raw"],
        row["tcp.len"],
        row["ip.id"],
        tuple(row[k] for k in FIELDS[6:]),
        hashlib.sha256(row["payload"]).hexdigest(),
    )


def paired_packets(before, after):
    """전후의 실제 디코딩 패킷을 대응시킨다. TCP 바이트 스트림은 재조립하지 않는다."""
    queues = collections.defaultdict(collections.deque)
    for row in before:
        if row["direction"] == "server_to_client":
            queues[packet_key(row)].append(row)
    matched, unmatched = [], []
    for row in after:
        queue = queues[packet_key(row)]
        if not queue:
            unmatched.append(row["frame.number"])
        else:
            matched.append((queue.popleft(), row))
    missing = [r["frame.number"] for queue in queues.values() for r in queue]
    inversions, last, seen = [], None, set()
    for pre, post in matched:
        if not post["tcp.len"]:
            continue
        identity = (post["tcp.seq_raw"], post["tcp.len"])
        if identity in seen:
            continue
        seen.add(identity)
        if last is not None and pre["frame.number"] < last[0]["frame.number"]:
            inversions.append(
                {
                    "pre_frames": [last[0]["frame.number"], pre["frame.number"]],
                    "post_frames": [last[1]["frame.number"], post["frame.number"]],
                    "raw_seq": [last[1]["tcp.seq_raw"], post["tcp.seq_raw"]],
                }
            )
        last = (pre, post)
    delays = [float(post["time"] - pre["time"]) for pre, post in matched if post["tcp.len"]]
    if any(d < 0 for d in delays):
        raise ValueError("주입 전후 시계/패킷 대응 모순")
    return {
        "matched_packets": len(matched),
        "unmatched_after": unmatched,
        "unmatched_before": sorted(missing),
        "arrival_inversions": inversions,
        "paired_data_delay_seconds": delays,
    }


def ack_rtt_samples(rows):
    frames = {r["frame.number"]: r for r in rows}
    counts = collections.Counter(
        (r["tcp.seq_raw"], r["tcp.len"])
        for r in rows
        if r["direction"] == "server_to_client" and r["tcp.len"]
    )
    samples = []
    for row in rows:
        value = row["tcp.analysis.ack_rtt"]
        if not value or row["direction"] != "client_to_server":
            continue
        delay = epoch(value)
        origin = frames.get(number(row["tcp.analysis.acks_frame"]))
        if not origin or origin["direction"] != "server_to_client" or not origin["tcp.len"]:
            continue
        if counts[(origin["tcp.seq_raw"], origin["tcp.len"])] != 1:
            continue
        if any(
            other is not origin
            and other["direction"] == "server_to_client"
            and other["tcp.len"]
            and (
                (other["tcp.seq_raw"] - origin["tcp.seq_raw"]) % MOD < origin["tcp.len"]
                or (origin["tcp.seq_raw"] - other["tcp.seq_raw"]) % MOD < other["tcp.len"]
            )
            for other in rows
        ):
            continue
        if not 0 <= delay <= 20 or abs(row["time"] - origin["time"] - delay) > Decimal("0.000001"):
            raise ValueError("ACK RTT 시각/참조 프레임 불일치")
        end = (origin["tcp.seq_raw"] + origin["tcp.len"]) % MOD
        if (row["tcp.ack_raw"] - end) % MOD >= 2**31:
            raise ValueError("ACK RTT 확인 바이트 범위 오류")
        samples.append(
            {
                "data_frame": origin["frame.number"],
                "ack_frame": row["frame.number"],
                "seconds": str(delay),
            }
        )
    return samples


def validate_payload_ranges(rows, initial, expected, complete, required=None):
    """기존 연결 분석기의 고정 바이트/seq 범위 검증을 계승한다. 재조립은 TShark가 담당한다."""
    coverage = {direction: bytearray(len(data)) for direction, data in expected.items()}
    for row in rows:
        direction = row["direction"]
        opposite = "server_to_client" if direction == "client_to_server" else "client_to_server"
        position = (row["tcp.seq_raw"] - initial[direction]) % MOD
        if position > len(expected[direction]) + 2:
            raise ValueError("TCP seq가 합성 전송 범위 밖")
        if row["tcp.flags.ack"] == "1":
            acknowledgment = (row["tcp.ack_raw"] - initial[opposite]) % MOD
            if not 1 <= acknowledgment <= len(expected[opposite]) + 2:
                raise ValueError("TCP ACK가 합성 전송 범위 밖")
        if not row["tcp.len"]:
            continue
        offset = (row["tcp.seq_raw"] - initial[direction] - 1) % MOD
        payload = row["payload"]
        if (
            offset + len(payload) > len(expected[direction])
            or expected[direction][offset : offset + len(payload)] != payload
        ):
            raise ValueError("TCP 페이로드/고정 앱 바이트 불일치")
        coverage[direction][offset : offset + len(payload)] = b"\x01" * len(payload)
    required = set(expected) if required is None else set(required)
    if complete and any(0 in coverage[key] for key in required):
        raise ValueError("완료 주장과 TCP 페이로드 범위 누락 모순")


def closure(rows, initial, expected):
    fins, resets = [], []
    for row in rows:
        if row["tcp.flags.reset"] == "1":
            resets.append(row["frame.number"])
        if row["tcp.flags.fin"] != "1":
            continue
        direction = row["direction"]
        end = (initial[direction] + 1 + len(expected[direction])) % MOD
        acks = [
            r["frame.number"]
            for r in rows
            if r["direction"] != direction
            and r["frame.number"] > row["frame.number"]
            and r["tcp.flags.ack"] == "1"
            and r["tcp.ack_raw"] == (end + 1) % MOD
        ]
        fins.append(
            {
                "frame": row["frame.number"],
                "direction": direction,
                "valid": (row["tcp.seq_raw"] + row["tcp.len"]) % MOD == end and bool(acks),
                "ack_frames": acks,
            }
        )
    valid = (
        not resets
        and {r["direction"] for r in fins} == set(expected)
        and all(r["valid"] for r in fins)
    )
    return {"complete": valid, "fins": fins, "rst_frames": resets}


def validate_app(log, config, role, capture):
    if (
        len(json.dumps(log).encode()) > 65536
        or any(log.get(k) != config[k] for k in ("profile", "scenario", "run_id"))
        or log.get("role") != role
    ):
        raise ValueError("앱 로그 상한/실행 혼합")
    events, previous = log.get("events"), 0
    if not isinstance(events, list) or not 0 < len(events) <= 256:
        raise ValueError("앱 로그 이벤트 상한/누락")
    identity = log.get("socket", {})
    if (
        identity.get("id") != f"{config['run_id']}:{role}:1"
        or type(identity.get("pid")) is not int
        or identity["pid"] <= 0
        or type(identity.get("fd")) is not int
        or not 0 <= identity["fd"] <= 65535
    ):
        raise ValueError("소켓 식별자/PID/FD 불일치")
    for index, item in enumerate(events, 1):
        if (
            item.get("event_id") != index
            or type(item.get("monotonic_ns")) is not int
            or item["monotonic_ns"] <= previous
        ):
            raise ValueError("앱 이벤트 순번/단조 시각")
        if (
            not epoch(capture["started_epoch"])
            <= epoch(item["epoch"])
            <= epoch(capture["ended_epoch"])
        ):
            raise ValueError("캡처 범위 밖 앱 이벤트")
        previous = item["monotonic_ns"]
    if len([e for e in events if e["event"] == "socket_open"]) != 1:
        raise ValueError("신규 소켓 상한 위반")


def compare(
    fields, follows, config, client, server, client_result, server_result, injection, final, body
):
    if (
        config.get("profile") != PROFILE
        or config.get("scenario") not in SCENARIOS
        or any(
            config.get(k) != v
            for k, v in {
                "connections": 1,
                "requests": 1,
                "body_bytes": 65536,
                "body_sha256": BODY_SHA256,
                "packets": 1024,
                "capture_seconds": 20,
                "file_bytes": MAX_BYTES,
            }.items()
        )
    ):
        raise ValueError("전용 프로파일/고정 상한 위반")
    for value in (client_result, server_result, injection):
        if any(value.get(k) != config[k] for k in ("profile", "scenario", "run_id")):
            raise ValueError("다른 실행/조건의 증거 혼합")
    if (
        not client_result.get("worker_complete")
        or not server_result.get("worker_complete")
        or not final.get("removed")
    ):
        raise ValueError("도구/캡처/주입 정리 실패")
    if client_result.get("role") != "client" or server_result.get("role") != "server":
        raise ValueError("worker 역할 혼합")
    verify_qdisc(config["scenario"], injection["after"])
    verify_qdisc(config["scenario"], final["before_removal"])
    for key in ("packets", "bytes", "drops"):
        if final["before_removal"][0][key] < injection["after"][0][key]:
            raise ValueError("qdisc 카운터 역행/실행 혼합")
    if type(injection.get("seed_supported")) is not bool or injection.get("seed") != (
        20261102 if config["scenario"] == "loss" and injection["seed_supported"] else None
    ):
        raise ValueError("seed 지원/사용값 모순")
    captures = {**server_result["captures"], **client_result["captures"]}
    validate_app(client, config, "client", captures["p"])
    validate_app(server, config, "server", captures["s"])
    client_port = client["socket"]["local"][1]
    if (
        type(client_port) is not int
        or not 0 < client_port <= 65535
        or client["socket"]["local"][0] != config["client"]
        or client["socket"]["remote"] != [config["server"], 8080]
        or server["socket"]["local"] != [config["server"], 8080]
        or server["socket"]["remote"] != [config["client"], client_port]
    ):
        raise ValueError("양쪽 소켓/주소 대응 불일치")
    rows = {
        p: parse_fields(fields[p], config, captures[p], p, client_port) for p in ("s", "p", "q")
    }
    first, second, third, syn_retrans = handshake(rows["s"])
    app = parse_follow(follows["s"], config, client_port)
    receiver = parse_follow(follows["q"], config, client_port)
    expected_response = response_head(config["run_id"]) + BODY
    initial = {"client_to_server": first["tcp.seq_raw"], "server_to_client": second["tcp.seq_raw"]}
    expected = {
        "client_to_server": request(config["run_id"]),
        "server_to_client": expected_response,
    }
    claimed_complete = bool(
        client_result.get("transfer_complete") and server_result.get("transfer_complete")
    )
    for prefix in ("s", "p", "q"):
        validate_payload_ranges(rows[prefix], initial, expected, claimed_complete and prefix != "q")
        if claimed_complete and prefix == "q":
            validate_payload_ranges(rows[prefix], initial, expected, True, {"server_to_client"})
    request_events = [e for e in client["events"] if e["event"] == "request_send_started"]
    if len(request_events) != 1:
        raise ValueError("앱 요청 1회 상한/기록 누락")
    if (
        not third["time"]
        <= epoch(injection["applied_epoch"])
        <= epoch(injection["verified_epoch"])
        <= epoch(request_events[0]["epoch"])
    ):
        raise ValueError("handshake/주입/요청 시각 순서 모순")
    if epoch(final["removal_epoch"]) < epoch(captures["q"]["ended_epoch"]):
        raise ValueError("캡처 종료 전 주입 해제")
    ending = closure(rows["s"], initial, expected)
    transfer = bool(
        client_result.get("transfer_complete")
        and server_result.get("transfer_complete")
        and body == BODY
        and app["client"] == request(config["run_id"])
        and app["server"] == expected_response
        and receiver["server"] == expected_response
        and receiver["client"] == b""
        and client.get("body") == {"bytes": 65536, "sha256": BODY_SHA256}
        and client.get("http")
        == {
            "status": 200,
            "content_length": 65536,
            "header_bytes": len(response_head(config["run_id"])),
        }
        and ending["complete"]
    )
    if len(body) > 65536:
        raise ValueError("실제 앱 본문 상한")
    pairs = paired_packets(rows["p"], rows["q"])
    packetization = all(r["tcp.len"] <= 1200 for group in rows.values() for r in group)
    baseline_packets = injection["after"][0]["packets"]
    drops = final["before_removal"][0]["drops"] - injection["after"][0]["drops"]
    counters = {
        prefix: {key: sum(r[key] == "1" for r in group) for key in EXTRA_FIELDS[10:15]}
        for prefix, group in rows.items()
    }
    retransmissions = sum(any(r[k] == "1" for k in EXTRA_FIELDS[10:13]) for r in rows["s"])
    metrics = client.get("metrics", {})
    groups = {
        kind: [e for e in client["events"] if e["event"] == kind]
        for kind in (
            "connect_started",
            "connect_returned",
            "request_send_started",
            "receive",
            "body_complete",
        )
    }
    for metric, left, right in (
        ("connect_seconds", "connect_started", "connect_returned"),
        ("first_byte_seconds", "request_send_started", "receive"),
        ("complete_seconds", "request_send_started", "body_complete"),
    ):
        if groups[right]:
            if len(groups[left]) != 1 or metrics.get(metric) is None:
                raise ValueError("앱 시간 기준 이벤트 누락")
            elapsed = (groups[right][0]["monotonic_ns"] - groups[left][0]["monotonic_ns"]) / 1e9
            if abs(metrics[metric] - elapsed) > 1e-9:
                raise ValueError("앱 이벤트/측정 시간 불일치")
    for key, upper in (
        ("connect_seconds", 3),
        ("first_byte_seconds", 15),
        ("complete_seconds", 15),
    ):
        value = metrics.get(key)
        if value is not None and (type(value) not in (int, float) or not 0 <= value <= upper):
            raise ValueError("앱 시간 상한/형식")
    if metrics.get("complete_seconds") is not None and (
        metrics.get("first_byte_seconds") is None
        or metrics["complete_seconds"] < metrics["first_byte_seconds"]
    ):
        raise ValueError("앱 응답 시각 순서")
    assessable = packetization and not pairs["unmatched_after"]
    observed = {
        "baseline": True,
        "delay": assessable
        and bool(pairs["paired_data_delay_seconds"])
        and min(pairs["paired_data_delay_seconds"]) >= 0.025,
        "loss": assessable and drops > 0 and bool(pairs["unmatched_before"]),
        "reorder": assessable and bool(pairs["arrival_inversions"]),
    }[config["scenario"]]
    return {
        "passed": transfer,
        "reasons": [] if transfer else ["transfer_failed"],
        "status": "transfer_failed"
        if not transfer
        else (
            "baseline"
            if config["scenario"] == "baseline"
            else ("effect_observed" if observed else "effect_unobserved")
        ),
        "effect_observed": observed if config["scenario"] != "baseline" else None,
        "measurement_complete": True,
        "transfer_complete": transfer,
        "packetization_sufficient": packetization,
        "seed_supported": injection["seed_supported"],
        "seed": injection["seed"],
        "metrics": metrics,
        "ack_rtt_samples": ack_rtt_samples(rows["s"]),
        "packet_counts": {p: len(v) for p, v in rows.items()},
        "handshake": [first["frame.number"], second["frame.number"], third["frame.number"]],
        "syn_retransmissions": syn_retrans,
        "retransmission_candidates": retransmissions,
        "tshark_candidates": counters,
        "closure": ending,
        "http": client.get("http"),
        "body_integrity": body == BODY,
        "packet_pairing": pairs,
        "qdisc_drop_delta": drops,
        "qdisc_packets_before_data": baseline_packets,
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "capture_limits": (
            "한 VM의 관측 구간. 설정 손실률/집계 drop을 원인별 실측 비율로 동일시하지 않음"
        ),
    }
