"""TShark 디코딩과 양쪽 앱 기록을 대조한다. PCAP 디코더/사건 모델은 만들지 않는다.

Why: 상태 코드·TCP ACK·한쪽 FIN만으로 연결 회복/앱 수신/완전 종료를 단정하지 않는다.
Constraints: PDML 1MiB/512패킷, 소켓 로그별 64KiB, 연결 최대 2개, 메시지별 256B.
Side-effects: 순수 오프라인 분석. 입력 오류는 예외, 관측 불일치는 failed로 전달한다.
"""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET

from connection_worker import (
    HALF_REQUEST,
    HALF_RESPONSE,
    PROFILE,
    RESET_REQUEST,
    SCENARIOS,
    http_bytes,
    split_http,
)
from sg_connection_timeline import epoch
from waf_packet_timeline import FIELDS, MAX_BYTES, analyze_csv

MOD = 2**32


def number(value, upper=MOD - 1):
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,9}", value):
        raise ValueError("정수 필드 형식 오류")
    if int(value) > upper:
        raise ValueError("정수 필드 범위 오류")
    return int(value)


def field(node, name, *, default=None, attribute="show"):
    values = [item.get(attribute) for item in node.iter("field") if item.get("name") == name]
    if not values and default is not None:
        return default
    if len(values) != 1 or values[0] is None:
        raise ValueError("필수 단일 디코딩 필드 누락/중복")
    return values[0]


def hex_bytes(value, maximum=65535):
    if (
        not isinstance(value, str)
        or len(value) > 2 * maximum
        or not re.fullmatch(r"(?:[a-fA-F0-9]{2})*", value)
    ):
        raise ValueError("바이트 필드 형식/상한 오류")
    return bytes.fromhex(value)


def parse_pdml(raw, *, start, end):
    if (
        not isinstance(raw, str)
        or len(raw.encode()) > MAX_BYTES
        or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", raw, re.IGNORECASE)
    ):
        raise ValueError("PDML 용량/선언 오류")
    root = ET.fromstring(raw)
    if root.tag != "pdml" or len(root) > 512 or not len(root):
        raise ValueError("PDML 루트/패킷 개수 오류")
    rows, messages = [], []
    for packet in root:
        if packet.tag != "packet":
            raise ValueError("PDML 패킷 형식 오류")
        row = {key: field(packet, key) for key in FIELDS}
        if number(field(packet, "frame.cap_len")) != number(field(packet, "frame.len")):
            raise ValueError("캡처 패킷 절단: 정상 통신 판정 금지")
        for key in FIELDS[6:]:
            row[key] = {"True": "1", "False": "0"}.get(row[key], row[key])
        row.update(
            {
                key: number(field(packet, key))
                for key in ("frame.number", "tcp.seq_raw", "tcp.ack_raw", "tcp.len")
            }
        )
        if not row["frame.number"] or row["tcp.len"] > 65535:
            raise ValueError("프레임/세그먼트 범위 오류")
        if rows and row["frame.number"] <= rows[-1]["frame.number"]:
            raise ValueError("프레임 중복/역순")
        row["payload"] = hex_bytes(field(packet, "tcp.payload", default="", attribute="value"))
        if len(row["payload"]) != row["tcp.len"]:
            raise ValueError("TCP 페이로드 길이/디코딩 불일치")
        row["retransmission"] = any(
            field(packet, key, default="0") in ("1", "True")
            for key in (
                "tcp.analysis.retransmission",
                "tcp.analysis.fast_retransmission",
                "tcp.analysis.spurious_retransmission",
            )
        )
        rows.append(row)
        for index, proto in enumerate(packet.findall("proto")):
            if proto.get("name") != "http":
                continue
            method = field(proto, "http.request.method", default="")
            status = field(proto, "http.response.code", default="")
            if (
                bool(method) == bool(status)
                or method not in ("", "GET")
                or status not in ("", "200", "403")
            ):
                raise ValueError("합성 HTTP 요청/응답 필드 오류")
            headers = {}
            for item in proto.iter("field"):
                if item.get("name") not in ("http.request.line", "http.response.line"):
                    continue
                line = hex_bytes(item.get("value", ""), 2048).decode("ascii").rstrip("\r\n")
                key, sep, value = line.partition(": ")
                if not sep or key.lower() in headers:
                    raise ValueError("HTTP 디코딩 헤더 중복/형식 오류")
                headers[key.lower()] = value
            messages.append(
                {
                    "frame": row["frame.number"],
                    "proto_index": index,
                    "stream": row["tcp.stream"],
                    "source": row["ip.src"],
                    "method": method,
                    "status": number(status or "0", 999),
                    "uri": field(proto, "http.request.uri", default=""),
                    "request_in": number(field(proto, "http.request_in", default="0")),
                    "content_length": number(field(proto, "http.content_length_header"), 256),
                    "headers": headers,
                    "body_hex": hex_bytes(
                        field(proto, "http.file_data", default="", attribute="value"), 256
                    ).hex(),
                }
            )
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows({key: row[key] for key in FIELDS} for row in rows)
    tcp = analyze_csv(output.getvalue(), start=start, end=end)
    return rows, messages, tcp


def events_by_connection(log, config, role, *, start, end):
    if len(json.dumps(log).encode()) > 65536:
        raise ValueError("소켓 로그 64KiB 초과")
    if (
        any(log.get(key) != config[key] for key in ("profile", "run_id", "scenario"))
        or log.get("role") != role
    ):
        raise ValueError("다른 실행/프로파일/역할의 소켓 로그")
    events = log.get("events")
    if not isinstance(events, list) or not 0 < len(events) <= 64:
        raise ValueError("소켓 이벤트 개수 오류")
    connections = {}
    previous = 0
    for index, item in enumerate(events, 1):
        connection = item.get("connection")
        if type(connection) is not int or connection not in (1, 2) or item.get("event_id") != index:
            raise ValueError("연결/이벤트 순번 오류")
        if item.get("socket_id") != f"{config['run_id']}:{role}:{connection}":
            raise ValueError("소켓 식별자 오류")
        if type(item.get("monotonic_ns")) is not int or item["monotonic_ns"] <= previous:
            raise ValueError("소켓 단조 시각 중복/역순")
        previous = item["monotonic_ns"]
        if not epoch(start) <= epoch(item["epoch"]) <= epoch(end):
            raise ValueError("관측 구간 밖 앱 기록")
        if (
            type(item.get("fd")) is not int
            or not 0 <= item["fd"] <= 65535
            or (type(item.get("pid")) is not int or not 0 < item["pid"] < 2**31)
        ):
            raise ValueError("소켓 FD/PID 오류")
        identity = tuple(
            item[key]
            for key in (
                "socket_id",
                "fd",
                "pid",
                "local_ip",
                "local_port",
                "remote_ip",
                "remote_port",
            )
        )
        group = connections.setdefault(connection, {"identity": identity, "events": []})
        if group["identity"] != identity:
            raise ValueError("같은 연결의 소켓/주소 변경: 재연결을 유지로 판정할 수 없음")
        if "data_hex" in item:
            raw = hex_bytes(
                item["data_hex"], 2048 if config["scenario"].startswith("http_") else 256
            )
            if item.get("bytes") != len(raw) or type(item.get("stream_offset")) is not int:
                raise ValueError("앱 메시지 길이/경계 오류")
        group["events"].append(item)
    return connections


def expected_events(mode, role, count):
    if mode.startswith("http_"):
        exchange = (
            ["send", "receive_http"] if role == "client" else ["request_receive", "response_send"]
        )
        client_first = mode == "http_reuse"
        end = (
            ["shutdown_write", "eof"]
            if (role == "client") == client_first
            else ["eof", "shutdown_write"]
        )
        return ["socket_open"] + exchange * count + end + ["socket_close"]
    if mode == "half_close":
        return (
            ["socket_open", "send", "shutdown_write", "receive", "eof", "socket_close"]
            if role == "client"
            else [
                "socket_open",
                "receive",
                "eof",
                "response_send",
                "shutdown_write",
                "socket_close",
            ]
        )
    return (
        ["socket_open", "send", "socket_reset", "socket_close"]
        if role == "client"
        else ["socket_open", "receive", "abortive_close", "socket_close"]
    )


def app_bytes(events, kinds):
    output = b""
    for item in events:
        if item["event"] in kinds:
            raw = hex_bytes(item["data_hex"], 6144)
            if item["stream_offset"] != len(output):
                raise ValueError("앱 메시지 스트림 경계 모순")
            output += raw
    return output


def handshake(packets):
    syns = [
        p
        for p in packets
        if p["direction"] == "client_to_server"
        and p["tcp.flags.syn"] == "1"
        and p["tcp.flags.ack"] == "0"
    ]
    if not syns or any(p["tcp.seq_raw"] != syns[0]["tcp.seq_raw"] for p in syns):
        raise ValueError("단일 연결 SYN 식별 불가")
    first = syns[0]
    synacks = [
        p
        for p in packets
        if p["direction"] == "server_to_client"
        and p["tcp.flags.syn"] == "1"
        and p["tcp.flags.ack"] == "1"
        and p["tcp.ack_raw"] == (first["tcp.seq_raw"] + 1) % MOD
        and p["frame.number"] > first["frame.number"]
    ]
    if not synacks or any(p["tcp.seq_raw"] != synacks[0]["tcp.seq_raw"] for p in synacks):
        raise ValueError("SYN-ACK 시퀀스 불일치")
    second = synacks[0]
    acknowledgments = [
        p
        for p in packets
        if p["direction"] == "client_to_server"
        and p["tcp.flags.ack"] == "1"
        and p["tcp.flags.syn"] == "0"
        and p["tcp.flags.reset"] == "0"
        and p["tcp.seq_raw"] == (first["tcp.seq_raw"] + 1) % MOD
        and p["tcp.ack_raw"] == (second["tcp.seq_raw"] + 1) % MOD
        and p["frame.number"] > second["frame.number"]
    ]
    if not acknowledgments:
        raise ValueError("3-way handshake 최종 ACK 불일치")
    return first, second, acknowledgments[0], len(syns) - 1


def compare(raw, config, worker, client, server, server_result):
    mode = config.get("scenario")
    run_id = config.get("run_id", "")
    if (
        mode not in SCENARIOS
        or config.get("profile") != PROFILE
        or not re.fullmatch(r"cs-connection-[a-f0-9]{32}", run_id)
    ):
        raise ValueError("실행/시나리오/프로파일 오류")
    count = 2 if mode == "http_close" else 1
    expected_config = {
        "requests": 3 if mode.startswith("http_") else 0,
        "connections": count,
        "concurrency": 1,
        "port": 8080,
        "capture_seconds": 15,
        "packets": 512,
        "file_bytes": MAX_BYTES,
        "connect_seconds": 3,
        "io_seconds": 2,
        "client_seconds": 10,
        "capture_file_rlimit_bytes": 65536,
    }
    if any(type(config.get(k)) is not int or config[k] != v for k, v in expected_config.items()):
        raise ValueError("연결 프로파일 상한 설정 오류")
    for result in (worker, server_result):
        if result.get("run_id") != run_id or result.get("scenario") != mode:
            raise ValueError("다른 실행의 완료 기록")
    capture = worker["capture"]
    start, end = capture["started_epoch"], capture["ended_epoch"]
    if not 0 < epoch(end) - epoch(start) <= 21:
        raise ValueError("캡처 시간 상한 오류")
    rows, messages, tcp = parse_pdml(raw, start=start, end=end)
    clients = events_by_connection(client, config, "client", start=start, end=end)
    servers = events_by_connection(server, config, "server", start=start, end=end)
    reasons = []
    if (
        not worker.get("worker_complete")
        or worker.get("error")
        or worker.get("cleanup_error")
        or not server_result.get("complete")
        or server_result.get("error")
    ):
        reasons.append("acquisition_or_server_failed")
    if (
        capture.get("exit") != 124
        or capture.get("kernel_dropped") != 0
        or capture.get("packets") != len(rows)
        or not len(rows) < 512
    ):
        reasons.append("capture_incomplete")
    if (
        set(clients) != set(range(1, count + 1))
        or set(servers) != set(clients)
        or len(tcp["streams"]) != count
    ):
        raise ValueError("계획 연결 수/소켓 로그/stream 불일치")
    if any(entry["input_out_of_order"] for entry in tcp["streams"].values()):
        reasons.append("packet_clock_out_of_order")
    for row in rows:
        outgoing = (
            row["ip.src"] == config["client"]
            and row["ip.dst"] == config["target"]
            and row["tcp.dstport"] == "8080"
        )
        incoming = (
            row["ip.src"] == config["target"]
            and row["ip.dst"] == config["client"]
            and row["tcp.srcport"] == "8080"
        )
        if not (outgoing or incoming):
            raise ValueError("소유 연결 밖 패킷")
        row["direction"] = "client_to_server" if outgoing else "server_to_client"
    summaries, used_streams = [], set()
    for connection in sorted(clients):
        ce, se = clients[connection]["events"], servers[connection]["events"]
        first, accepted = ce[0], se[0]
        client_pair = (
            first["local_ip"],
            first["local_port"],
            first["remote_ip"],
            first["remote_port"],
        )
        server_pair = (
            accepted["remote_ip"],
            accepted["remote_port"],
            accepted["local_ip"],
            accepted["local_port"],
        )
        if (
            client_pair != server_pair
            or client_pair[0] != config["client"]
            or client_pair[2:] != (config["target"], 8080)
        ):
            raise ValueError("양쪽 소켓/설정 좌표 불일치")
        selected = [
            p
            for p in rows
            if (p["tcp.srcport"] if p["direction"] == "client_to_server" else p["tcp.dstport"])
            == str(first["local_port"])
        ]
        streams = {p["tcp.stream"] for p in selected}
        if len(streams) != 1 or streams & used_streams:
            raise ValueError("소켓과 TCP stream의 1:1 대응 실패")
        stream = next(iter(streams))
        used_streams.add(stream)
        ordinals = ((1, 2) if connection == 1 else (3,)) if mode == "http_close" else (1, 2, 3)
        for events, role in ((ce, "client"), (se, "server")):
            if [e["event"] for e in events] != expected_events(mode, role, len(ordinals)):
                reasons.append("application_lifecycle_mismatch")
            if mode.startswith("http_"):
                for kind in (
                    ("send", "receive_http")
                    if role == "client"
                    else ("request_receive", "response_send")
                ):
                    relevant = [event for event in events if event["event"] == kind]
                    if [event.get("ordinal") for event in relevant] != list(ordinals):
                        reasons.append("application_http_ordinal_mismatch")
                    for ordinal, event in zip(ordinals, relevant, strict=False):
                        response = kind in ("receive_http", "response_send")
                        status = (403 if ordinal == 2 else 200) if response else None
                        close = response and mode == "http_close" and ordinal in (2, 3)
                        expected = http_bytes(run_id, ordinal, status=status, close=close)
                        if hex_bytes(event["data_hex"], 2048) != expected:
                            reasons.append("application_http_message_mismatch")
                        if kind == "receive_http":
                            parsed = split_http(expected, response=True)[0]
                            if (
                                event.get("status") != status
                                or event.get("headers") != parsed["headers"]
                                or event.get("header_bytes") != parsed["header_bytes"]
                            ):
                                reasons.append("application_http_metadata_mismatch")
        cdata = app_bytes(ce, {"send"})
        received = app_bytes(se, {"request_receive", "receive"})
        sdata = app_bytes(se, {"response_send"})
        returned = app_bytes(ce, {"receive_http", "receive"})
        if cdata != received or sdata != returned:
            reasons.append("application_receive_mismatch")
        syn, synack, ack, retrans_syn = handshake(selected)
        initial = {
            "client_to_server": syn["tcp.seq_raw"],
            "server_to_client": synack["tcp.seq_raw"],
        }
        data = {"client_to_server": cdata, "server_to_client": sdata}
        coverage = {key: bytearray(len(value)) for key, value in data.items()}
        seen = dict.fromkeys(initial, 0)
        for packet in selected:
            direction = packet["direction"]
            opposite = "server_to_client" if direction == "client_to_server" else "client_to_server"
            position = (packet["tcp.seq_raw"] - initial[direction]) % MOD
            ack_position = (packet["tcp.ack_raw"] - initial[opposite]) % MOD
            if position > len(data[direction]) + 2 or (
                packet["tcp.flags.ack"] == "1" and not 1 <= ack_position <= seen[opposite]
            ):
                reasons.append("sequence_or_ack_outside_observed_bytes")
            seen[direction] = max(
                seen[direction],
                position
                + packet["tcp.len"]
                + int(packet["tcp.flags.syn"])
                + int(packet["tcp.flags.fin"]),
            )
            if not packet["payload"]:
                continue
            offset = (packet["tcp.seq_raw"] - initial[direction] - 1) % MOD
            payload = packet["payload"]
            if (
                packet["frame.number"] < ack["frame.number"]
                or offset + len(payload) > len(data[direction])
                or data[direction][offset : offset + len(payload)] != payload
            ):
                reasons.append("packet_application_bytes_mismatch")
                continue
            coverage[direction][offset : offset + len(payload)] = b"\x01" * len(payload)
        if any(0 in value for value in coverage.values()):
            reasons.append("packet_payload_missing")
        fins = [p for p in selected if p["tcp.flags.fin"] == "1"]
        resets = [p for p in selected if p["tcp.flags.reset"] == "1"]
        fin_events = []
        for fin in fins:
            position = (fin["tcp.seq_raw"] + fin["tcp.len"]) % MOD
            fin_acks = [
                p
                for p in selected
                if p["direction"] != fin["direction"]
                and p["tcp.flags.ack"] == "1"
                and p["tcp.ack_raw"] == (position + 1) % MOD
                and p["frame.number"] > fin["frame.number"]
            ]
            if (
                position != (initial[fin["direction"]] + 1 + len(data[fin["direction"]])) % MOD
                or not fin_acks
            ):
                reasons.append("fin_sequence_or_ack_mismatch")
            fin_events.append(
                {
                    "frame": fin["frame.number"],
                    "direction": fin["direction"],
                    "seq_raw": fin["tcp.seq_raw"],
                    "ack_raw": fin["tcp.ack_raw"],
                    "ack_frames": [p["frame.number"] for p in fin_acks],
                }
            )
        if mode == "established_rst":
            expected_reset = [
                p
                for p in resets
                if p["direction"] == "server_to_client"
                and p["frame.number"] > ack["frame.number"]
                and p["tcp.seq_raw"] == (initial["server_to_client"] + 1) % MOD
                and p["tcp.flags.ack"] == "1"
                and p["tcp.ack_raw"] == (initial["client_to_server"] + 1 + len(cdata)) % MOD
            ]
            if (
                cdata != RESET_REQUEST
                or not expected_reset
                or fins
                or not any(e["event"] == "socket_reset" and e.get("errno") == 104 for e in ce)
                or not any(
                    e["event"] == "abortive_close" and e.get("linger_hex") == "0100000000000000"
                    for e in se
                )
            ):
                reasons.append("established_reset_mismatch")
        elif resets or {p["direction"] for p in fins} != set(initial):
            reasons.append("graceful_close_mismatch")
        if mode == "half_close":
            from_client = [p for p in fins if p["direction"] == "client_to_server"]
            reverse_data = [
                p for p in selected if p["direction"] == "server_to_client" and p["payload"]
            ]
            if (
                cdata != HALF_REQUEST
                or sdata != HALF_RESPONSE
                or not from_client
                or not reverse_data
                or min(p["frame.number"] for p in reverse_data) <= from_client[0]["frame.number"]
            ):
                reasons.append("half_close_reverse_data_missing")
        http = [m for m in messages if m["stream"] == stream]
        if mode.startswith("http_"):
            if [bool(m["method"]) for m in http] != [True, False] * len(ordinals):
                reasons.append("http_sequential_exchange_mismatch")
            requests = [m for m in http if m["method"]]
            responses = [m for m in http if m["status"]]
            if len(requests) != len(ordinals) or len(responses) != len(ordinals):
                reasons.append("http_message_count_mismatch")
            for ordinal, request, response in zip(ordinals, requests, responses, strict=False):
                close = mode == "http_close" and ordinal in (2, 3)
                for message in (request, response):
                    if message["headers"].get("x-run-id") != run_id or message["headers"].get(
                        "x-sequence"
                    ) != str(ordinal):
                        reasons.append("http_message_identity_mismatch")
                if (
                    request["source"] != config["client"]
                    or request["uri"] != f"/{ordinal}"
                    or request["content_length"] != 0
                    or response["source"] != config["target"]
                    or response["status"] != (403 if ordinal == 2 else 200)
                    or response["request_in"] != request["frame"]
                    or response["frame"] <= request["frame"]
                    or response["headers"].get("connection") != ("close" if close else "keep-alive")
                    or hex_bytes(response["body_hex"]) != f"synthetic-{ordinal}\n".encode()
                    or response["content_length"] != len(hex_bytes(response["body_hex"]))
                ):
                    reasons.append("http_exchange_mismatch")
            expected_first_fin = "server_to_client" if mode == "http_close" else "client_to_server"
            if (
                not fins
                or fins[0]["direction"] != expected_first_fin
                or (responses and fins[0]["frame.number"] < responses[-1]["frame"])
            ):
                reasons.append("http_fin_order_mismatch")
        elif http:
            reasons.append("unexpected_http")
        summaries.append(
            {
                "connection": connection,
                "stream": stream,
                "client_socket_id": first["socket_id"],
                "server_socket_id": accepted["socket_id"],
                "client_port": first["local_port"],
                "handshake_frames": [p["frame.number"] for p in (syn, synack, ack)],
                "fin": fin_events,
                "rst": [
                    {
                        key: p[key]
                        for key in ("frame.number", "direction", "tcp.seq_raw", "tcp.ack_raw")
                    }
                    for p in resets
                ],
                "http": http,
                "syn_retransmissions": retrans_syn,
                "client_bytes": len(cdata),
                "server_bytes": len(sdata),
            }
        )
    return {
        "profile": PROFILE,
        "run_id": run_id,
        "scenario": mode,
        "passed": not reasons,
        "reasons": sorted(set(reasons)),
        "connections": summaries,
        "packet_count": len(rows),
        "retransmissions": sum(p["retransmission"] for p in rows),
        "observation_seconds": str(epoch(end) - epoch(start)),
        "tcp": tcp,
        "limitations": (
            "재전송 0은 해당 캡처 구간의 관측값이다. 커널·bridge·오프로딩·캡처 한계가 있으며 "
            "AWS 원인·전파·SLA·과거 연결 재사용의 증거가 아니다."
        ),
    }
