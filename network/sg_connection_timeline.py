"""SG 교체 관측의 합성 메시지 메타데이터를 오프라인 대조한다. AWS 호출은 없다."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import re
from decimal import Decimal
from pathlib import Path

from waf_packet_timeline import MAX_BYTES, MAX_ROWS, analyze_csv

FIELDS = (
    "event_id",
    "connection",
    "socket_id",
    "client_ip",
    "client_port",
    "server_ip",
    "server_port",
    "sequence",
    "event",
    "epoch",
    "bytes",
)
EVENTS = {
    "socket_open",
    "send",
    "server_receive",
    "response_receive",
    "timeout",
    "socket_close",
    "socket_reset",
    "observed_established",
    "tcp_ack",
}
MESSAGE_EVENTS = {"send", "server_receive", "response_receive", "tcp_ack"}


def epoch(value: str) -> Decimal:
    """초 단위 epoch의 모호한 표기를 거부한다. 입력 원문은 예외에 포함하지 않는다."""
    if not re.fullmatch(r"[0-9]{1,12}(?:\.[0-9]{1,9})?", value):
        raise ValueError("시각 형식 오류")
    return Decimal(value)


def integer(value: str, lower: int, upper: int) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]{0,8}", value) or not lower <= int(value) <= upper:
        raise ValueError("정수 범위 오류")
    return int(value)


def analyze_events(
    raw: str,
    *,
    start: str,
    end: str,
    change_start: str,
    api_complete: str,
    sg_confirmed: str,
    clock_error: str,
) -> dict:
    """동일 소켓·메시지 순번을 대조하되 데이터 플레인 효력이나 SG 원인을 확정하지 않는다.

    Why: send/ESTABLISHED/ACK와 서버 수신·응답은 서로 다른 증거이므로 합치지 않는다.
    Constraints: IPv4, A/B/R 각각 소켓 1개, 20메시지/256바이트, 120초/1MiB/10000행.
    Side-effects: 외부 I/O 없음. 시계 오차는 장비별 최대 절대 오차(초); 모순은 실패로 전파.
    """
    lower, upper = epoch(start), epoch(end)
    change, api, confirmed, error = map(
        epoch, (change_start, api_complete, sg_confirmed, clock_error)
    )
    if not lower <= change <= api <= confirmed <= upper or not 0 < upper - lower <= 120:
        raise ValueError("관측 구간 또는 제어 시각 오류")
    if error > 5 or len(raw.encode("utf-8")) > MAX_BYTES:
        raise ValueError("시계 오차 또는 입력 용량 초과")
    reader = csv.DictReader(io.StringIO(raw))
    if tuple(reader.fieldnames or ()) != FIELDS:
        raise ValueError("허용된 합성 메타데이터 필드만 필요합니다")
    records, identities, connections = [], {}, {}
    duplicate_count = 0
    for count, row in enumerate(reader, start=1):
        if count > MAX_ROWS or None in row or any(v is None for v in row.values()):
            raise ValueError("행 수 또는 필드 수 오류")
        event_id = integer(row["event_id"], 1, 999999999)
        socket_id = integer(row["socket_id"], 1, 999999999)
        sequence = integer(row["sequence"], 0, 20)
        size = integer(row["bytes"], 0, 256)
        stamp = epoch(row["epoch"])
        label, kind = row["connection"], row["event"]
        if label not in {"A", "B", "R"} or kind not in EVENTS or not lower <= stamp <= upper:
            raise ValueError("연결·이벤트·시각 오류")
        if kind in MESSAGE_EVENTS:
            if not sequence or not size:
                raise ValueError("메시지 순번·바이트 누락")
        elif sequence or size:
            raise ValueError("상태 이벤트에 메시지 필드 사용 금지")
        try:
            client_ip = str(ipaddress.IPv4Address(row["client_ip"]))
            server_ip = str(ipaddress.IPv4Address(row["server_ip"]))
        except ValueError:
            raise ValueError("IPv4 주소 오류") from None
        client_port = integer(row["client_port"], 1, 65535)
        server_port = integer(row["server_port"], 1, 65535)
        identity = (socket_id, client_ip, client_port, server_ip, server_port)
        connection = connections.setdefault(label, {"identity": identity, "events": []})
        if identity != connection["identity"]:
            raise ValueError("동일 연결의 소켓·주소·포트 변경: 재연결을 유지로 판정할 수 없음")
        record = {
            "event_id": event_id,
            "connection": label,
            "socket_id": socket_id,
            "client_ip": client_ip,
            "client_port": client_port,
            "server_ip": server_ip,
            "server_port": server_port,
            "sequence": sequence,
            "event": kind,
            "epoch": str(stamp),
            "bytes": size,
        }
        if event_id in identities:
            if identities[event_id] != record:
                raise ValueError("중복 이벤트 식별자의 내용 충돌")
            duplicate_count += 1
        else:
            identities[event_id] = record
            connection["events"].append(record)
        records.append(record)
    out_of_order = any(
        epoch(a["epoch"]) > epoch(b["epoch"]) for a, b in zip(records, records[1:], strict=False)
    )
    if connections:
        reference = next(iter(connections.values()))["identity"]
        for connection in connections.values():
            if (
                connection["identity"][1] != reference[1]
                or connection["identity"][3:] != reference[3:]
            ):
                raise ValueError("단일 클라이언트·서버·서비스만 허용")
        pairs = list(connections.values())
        for index, first in enumerate(pairs):
            for second in pairs[index + 1 :]:
                if (
                    first["identity"][0] == second["identity"][0]
                    or first["identity"][2] == second["identity"][2]
                ):
                    raise ValueError("새 연결은 별도 소켓·클라이언트 포트 필요")
    summaries = {}
    for label, connection in connections.items():
        ordered = sorted(connection["events"], key=lambda item: epoch(item["epoch"]))
        opens = [item for item in ordered if item["event"] == "socket_open"]
        if len(opens) > 1:
            raise ValueError("연결당 소켓 생성은 한 번만 허용")
        terminal_times = [
            epoch(item["epoch"])
            for item in ordered
            if item["event"] in {"socket_close", "socket_reset"}
        ]
        # 클라이언트 소켓의 같은 시계로 기록된 송신·앱 수신은 수명 안에 있어야 한다.
        # 서버의 지연 수신과 캡처 ACK는 클라이언트 close 후에도 관측될 수 있어 제외한다.
        if any(
            item["event"] in {"send", "response_receive"}
            and (
                (opens and epoch(item["epoch"]) < epoch(opens[0]["epoch"]))
                or any(epoch(item["epoch"]) > terminal for terminal in terminal_times)
            )
            for item in ordered
        ):
            raise ValueError("클라이언트 소켓 수명 밖 송신 또는 응답 수신 기록")
        messages = {}
        for item in ordered:
            if item["event"] not in MESSAGE_EVENTS:
                continue
            message = messages.setdefault(item["sequence"], {})
            if item["event"] in message:
                raise ValueError("동일 메시지 단계 중복: 고유 이벤트 식별자 확인 필요")
            message[item["event"]] = item
        results = []
        for sequence, message in sorted(messages.items()):
            sizes = {item["bytes"] for item in message.values()}
            if len(sizes) != 1:
                raise ValueError("합성 echo 메시지 바이트 불일치")
            send = message.get("send")
            receive = message.get("server_receive")
            response = message.get("response_receive")
            chain = [item for item in (send, receive, response) if item]
            # 각 두 시각의 최대 오차 합은 2×error다. 단계마다 이를 누적하면
            # 송신→응답의 전체 역전을 허용하므로 비인접 단계까지 같은 한도로 대조한다.
            if any(
                epoch(a["epoch"]) > epoch(b["epoch"]) + 2 * error
                for index, a in enumerate(chain)
                for b in chain[index + 1 :]
            ):
                raise ValueError("메시지 인과 시각 모순")
            post = bool(send and epoch(send["epoch"]) > confirmed + 2 * error)
            results.append(
                {
                    "sequence": sequence,
                    "stages": message,
                    "sent_after_sg_confirmation_with_clock_margin": post,
                    "roundtrip_recorded": bool(send and receive and response),
                    "tcp_ack_recorded": "tcp_ack" in message,
                    "observation": (
                        "합성 메시지 송신·서버 수신·응답 기록 대조 완료"
                        if send and receive and response
                        else "증거 부족: 누락 단계 확인 필요"
                    ),
                }
            )
        send_times = [epoch(item["epoch"]) for item in ordered if item["event"] == "send"]
        baseline = bool(
            label == "A"
            and opens
            and epoch(opens[0]["epoch"]) + 2 * error < change
            and any(
                item["roundtrip_recorded"]
                and all(
                    epoch(stage["epoch"]) + 2 * error < change for stage in item["stages"].values()
                )
                for item in results
            )
        )
        post_roundtrips = [
            item["sequence"]
            for item in results
            if item["roundtrip_recorded"] and item["sent_after_sg_confirmation_with_clock_margin"]
        ]
        summaries[label] = {
            "events": ordered,
            "socket_open_recorded": bool(opens),
            "baseline_roundtrip_before_change_recorded": baseline,
            "new_socket_after_confirmation_recorded": bool(
                label in {"B", "R"} and opens and epoch(opens[0]["epoch"]) > confirmed + 2 * error
            ),
            "messages": results,
            "post_confirmation_roundtrip_sequences": post_roundtrips,
            "send_count": len(send_times),
            "minimum_send_interval_seconds": min(
                (format(b - a, "f") for a, b in zip(send_times, send_times[1:], strict=False)),
                key=Decimal,
                default=None,
            ),
            "observation": (
                "기존 A의 교체 후 새 메시지 왕복 기록 있음; 소켓·SYN·캡처 증거 별도 대조 필요"
                if baseline and post_roundtrips
                else "증거 부족: 기존 연결 유지·전달·종료 확정 불가"
            ),
        }
    return {
        "observation_start_epoch": str(lower),
        "observation_end_epoch": str(upper),
        "change_request_start_epoch": str(change),
        "api_complete_epoch": str(api),
        "sg_list_confirmed_epoch": str(confirmed),
        "clock_error_seconds": str(error),
        "input_out_of_order": out_of_order,
        "duplicate_event_count": duplicate_count,
        "event_count": len(records),
        "connections": summaries,
        "sg_cause": "미확정: API 완료·SG 목록 확인은 패킷 효력 시각이 아님",
        "limitations": (
            "메타데이터 선언은 소켓 동일성·payload 일치·FIN/RST·handshake의 독립 증명이 아님"
        ),
    }


def read_bounded(path: Path) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("입력 용량 초과")
    return raw


def write_report(source: Path, output: Path, *, packets: Path | None = None, **times: str) -> None:
    """허용 메타데이터만 새 파일로 기록한다. 실패한 부분 출력·기존 증거는 삭제하지 않는다."""
    raw = read_bounded(source)
    report = analyze_events(raw.decode("utf-8"), **times)
    report["source_sha256"] = hashlib.sha256(raw).hexdigest()
    if packets is not None:
        packet_raw = read_bounded(packets)
        report["tcp"] = analyze_csv(
            packet_raw.decode("utf-8"), start=times["start"], end=times["end"]
        )
        report["packet_csv_sha256"] = hashlib.sha256(packet_raw).hexdigest()
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--packets", type=Path)
    for name in ("start", "end", "change-start", "api-complete", "sg-confirmed", "clock-error"):
        parser.add_argument("--" + name, required=True)
    args = vars(parser.parse_args())
    source, output, packets = (args.pop(name) for name in ("source", "output", "packets"))
    try:
        write_report(source, output, packets=packets, **args)
    except (OSError, UnicodeError, ValueError, csv.Error):
        parser.exit(2, "분석 실패: 메타데이터·시계·상한·새 출력 경로를 확인하세요\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
