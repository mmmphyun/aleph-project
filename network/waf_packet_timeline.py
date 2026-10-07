"""허용 필드만 추출한 TCP CSV를 오프라인 분석한다. HTTP/WAF 원인은 추정하지 않는다."""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
from decimal import Decimal
from pathlib import Path

FIELDS = (
    "frame.time_epoch",
    "tcp.stream",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
)
MAX_BYTES = 1024 * 1024
MAX_ROWS = 10000


def analyze_csv(raw: str, *, start: str, end: str) -> dict:
    """동일 캡처의 관측 구간 내 플래그를 보존하며 누락·역순 입력을 숨기지 않는다.

    Why: FIN은 반쪽 연결 종료일 수 있어 완전 종료나 WAF 강제 종료로 승격하지 않는다.
    Constraints: IPv4 TCP, 최대 1MiB/10000행, epoch 초 소수 9자리; QUIC/TLS 키 제외.
    Side-effects: 외부 호출 없음. 잘못된 열·행은 원문 없이 ValueError로 전파한다.
    """
    if len(raw.encode("utf-8")) > MAX_BYTES:
        raise ValueError("입력 용량 초과")

    def epoch(value: str) -> Decimal:
        if not re.fullmatch(r"[0-9]{1,12}(?:\.[0-9]{1,9})?", value):
            raise ValueError("시각 형식 오류")
        return Decimal(value)

    lower, upper = epoch(start), epoch(end)
    if lower >= upper:
        raise ValueError("관측 구간 오류")
    reader = csv.DictReader(io.StringIO(raw))
    if tuple(reader.fieldnames or ()) != FIELDS:
        raise ValueError("허용된 TCP 필드만 필요합니다")
    streams: dict[str, dict] = {}
    rows = 0
    for row in reader:
        rows += 1
        if rows > MAX_ROWS or None in row or any(v is None for v in row.values()):
            raise ValueError("행 수 또는 필드 수 오류")
        timestamp = epoch(row[FIELDS[0]])
        if not lower <= timestamp <= upper:
            raise ValueError("관측 구간 밖 패킷")
        stream = row[FIELDS[1]]
        if not re.fullmatch(r"[0-9]{1,9}", stream):
            raise ValueError("스트림 번호 오류")
        endpoints = []
        for ip_key, port_key in ((FIELDS[2], FIELDS[3]), (FIELDS[4], FIELDS[5])):
            try:
                address = str(ipaddress.IPv4Address(row[ip_key]))
            except ValueError:
                raise ValueError("IPv4 주소 오류") from None
            port = row[port_key]
            if not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
                raise ValueError("TCP 포트 오류")
            endpoints.append(f"{address}:{port}")
        flags = [row[key] for key in FIELDS[6:]]
        if any(flag not in ("0", "1") for flag in flags):
            raise ValueError("TCP 플래그 오류")
        pair = sorted(endpoints)
        entry = streams.setdefault(stream, {"endpoints": pair, "packets": []})
        if entry["endpoints"] != pair:
            raise ValueError("동일 스트림의 주소·포트 불일치")
        entry["packets"].append(
            {
                "epoch": str(timestamp),
                "offset_seconds": format(timestamp - lower, "f"),
                "source": endpoints[0],
                "destination": endpoints[1],
                "flags": [
                    name
                    for name, value in zip(("SYN", "ACK", "FIN", "RST"), flags, strict=True)
                    if value == "1"
                ],
            }
        )
    for entry in streams.values():
        # 정렬은 후처리에만 적용한다. 입력 재정렬 사실도 보고해 캡처 시계 문제를 드러낸다.
        packets = entry["packets"]
        entry["input_out_of_order"] = any(
            Decimal(a["epoch"]) > Decimal(b["epoch"])
            for a, b in zip(packets, packets[1:], strict=False)
        )
        packets.sort(key=lambda p: Decimal(p["epoch"]))
        entry["fin_observed"] = any("FIN" in p["flags"] for p in packets)
        entry["rst_observed"] = any("RST" in p["flags"] for p in packets)
        entry["observation"] = (
            "FIN/RST 관측: 송신 주체·종료 원인은 별도 대조 필요"
            if entry["fin_observed"] or entry["rst_observed"]
            else "관측 구간 내 종료 없음: 캡처 누락 여부 별도 확인 필요"
        )
    return {
        "observation_start_epoch": str(lower),
        "observation_end_epoch": str(upper),
        "packet_count": rows,
        "streams": streams,
        "http_status": "PCAP 파생 TCP 필드로 판정 불가",
        "waf_cause": "미확정",
        "handshake": "SYN/ACK 후보를 보고서에서 seq/ack와 대조; 자동 확정하지 않음",
    }


def write_report(source: Path, output: Path, *, start: str, end: str) -> None:
    """입력 상한과 독점 생성을 적용한다. 기존 증거는 보존하고 외부 도구로 폴백하지 않는다."""
    with source.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("입력 용량 초과")
    result = analyze_csv(raw.decode("utf-8"), start=start, end=end)
    # 검증이 끝난 뒤 새 파일만 생성한다. 기록 실패의 부분 결과도 자동 삭제하지 않는다.
    with output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    args = parser.parse_args()
    try:
        write_report(args.source, args.output, start=args.start, end=args.end)
    except (OSError, UnicodeError, ValueError, csv.Error):
        # 경로·원시 행·진단 문자열에는 비밀이 들어갈 수 있어 콘솔에 재출력하지 않는다.
        parser.exit(2, "분석 실패: 입력 규격·관측 구간·용량·새 출력 경로를 확인하세요\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
