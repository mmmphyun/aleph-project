#!/usr/bin/env python3
"""기존 계측 증거를 읽어 실행별 왕복 관측을 요약한다. 외부 호출·패킷 수집은 없다.

Why: 제어 API 완료와 통신 회복, 프로세스 호출과 패킷 송신을 분리해 과대 판정을 막는다.
Constraints: 메타데이터 1MiB/10000행, 러너 512행, 증거 32개, 파일당 최대 1GiB.
Side-effects: 입력은 읽기 전용이며 새 요약만 원자적으로 게시한다. 검증/I/O 오류는 전파한다.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from demo_attack_runner import MAX_EVENT_BYTES, MAX_EVENTS
from sg_connection_timeline import epoch, read_bounded
from waf_packet_timeline import FIELDS, MAX_BYTES, MAX_ROWS, analyze_csv

INPUT_SCHEMA = "cloudshield-roundtrip-input-v1"
OUTPUT_SCHEMA = "cloudshield-roundtrip-summary-v1"
MAX_FILES = 32
MAX_FILE_BYTES = 1024**3
KINDS = {
    "baseline",
    "attack_invoked",
    "first_attack",
    "probe",
    "recovery_requested",
    "recovery_started",
    "recovery_api_completed",
    "configuration_verified",
    "recovery_attested",
    "observation_ended",
    "waf_block",
}
SOURCES = {
    "tcp_probe",
    "http_probe",
    "pcap_tcp",
    "pcap_http",
    "http_request",
    "cloud_a",
    "cloud_b",
    "operator",
    "runner",
}
FORMATS = {"runner_events", "ssh_manifest", "web_scan", "tcp_csv", "observations", "opaque"}
OUTCOMES = {"connected", "timeout", "refused", "network_error", "rst", "fin", "http"}
ISO = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.[0-9]{1,9})?(Z|\+00:00|\+0000)")


def identifier(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,100}", value):
        raise ValueError("식별자 형식 오류")
    return value


def decimal_string(value: Any) -> Decimal:
    if not isinstance(value, str):
        raise ValueError("정밀 수치는 문자열이어야 합니다")
    return epoch(value)


def timestamp(value: Any, *, resolution: Any = "infer") -> dict:
    """정수 초와 소수부를 분리해 datetime의 마이크로초 절삭을 피한다.

    원본 소수 자릿수는 해상도 상한의 근거일 뿐 시계 정확도가 아니다. 이미 정규화된
    러너 시각은 resolution=None으로 보존하며, 더 세밀한 원본이 있다고 추측하지 않는다.
    """
    if not isinstance(value, str):
        raise ValueError("시각은 원본 문자열이어야 합니다")
    match = ISO.fullmatch(value)
    if match:
        base, fraction, _ = match.groups()
        delta = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC) - datetime(
            1970, 1, 1, tzinfo=UTC
        )
        seconds = Decimal(delta.days * 86400 + delta.seconds) + Decimal("0" + (fraction or ""))
        decimal_string(format(seconds, "f"))
        digits = len(fraction) - 1 if fraction else 0
    else:
        seconds = decimal_string(value)
        digits = len(value.split(".")[1]) if "." in value else 0
    inferred = Decimal(1).scaleb(-digits)
    quantum = (
        inferred
        if resolution == "infer"
        else (None if resolution is None else decimal_string(resolution))
    )
    if quantum is not None and (
        quantum not in {Decimal(1).scaleb(-n) for n in range(10)}
        or seconds % quantum != 0
        or quantum < inferred
    ):
        raise ValueError("원본 시각과 해상도 불일치")
    whole = int(seconds)
    try:
        base = (datetime(1970, 1, 1, tzinfo=UTC) + timedelta(seconds=whole)).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
    except (OverflowError, ValueError):
        raise ValueError("지원 시각 범위 초과") from None
    fraction = format(seconds - whole, f".{digits}f")[1:] if digits else ""
    return {
        "raw": value,
        "utc": base + fraction + "Z",
        "epoch_seconds": format(seconds, "f"),
        "resolution_seconds": None if quantum is None else format(quantum, "f"),
    }


def strict_json(raw: bytes | str) -> Any:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("JSON 중복 키")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("비유한 JSON 수치")

    return json.loads(raw, object_pairs_hook=pairs, parse_float=Decimal, parse_constant=constant)


def fingerprint(path: Path, expected: str) -> tuple[dict, bytes | None]:
    """열린 일반 파일을 청크 해시하고 메타데이터 파서에는 같은 읽기의 바이트를 전달한다.

    파일 교체/변경과 상한 초과는 실패한다. 해시는 바이트 식별이며 발급 주체 인증이 아니다.
    """
    if path.is_symlink() or not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise ValueError("증거 경로 또는 SHA-256 오류")
    digest, count, chunks = hashlib.sha256(), 0, []
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            raise ValueError("일반 파일 또는 증거 용량 상한 위반")
        for chunk in iter(lambda: stream.read(MAX_BYTES), b""):
            count += len(chunk)
            if count > MAX_FILE_BYTES:
                raise ValueError("증거 용량 초과")
            digest.update(chunk)
            if count <= MAX_BYTES:
                chunks.append(chunk)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ino,
    ) or count != before.st_size:
        raise ValueError("읽는 동안 증거 변경")
    if digest.hexdigest() != expected:
        raise ValueError("증거 SHA-256 불일치")
    return {"sha256": digest.hexdigest(), "bytes": count}, (
        b"".join(chunks) if count <= MAX_BYTES else None
    )


def event(context, evidence, key, kind, value, *, source, resolution="infer", **details):
    if kind not in KINDS or source not in SOURCES:
        raise ValueError("관측 종류 또는 출처 오류")
    clock = evidence["clock_id"]
    return {
        "event_id": evidence["evidence_id"] + ":" + str(key),
        "kind": kind,
        "time": timestamp(value, resolution=resolution),
        "clock_id": clock,
        "source": {"evidence_id": evidence["evidence_id"], "locator": str(key), "kind": source},
        **details,
    }


def check_probe(item, scenario):
    allowed_sources = (
        {"tcp_probe", "pcap_tcp"} if scenario == "ssh" else {"http_probe", "pcap_http"}
    )
    if item["source"]["kind"] not in allowed_sources:
        raise ValueError("통신 관측에는 해당 프로토콜의 직접 관측 출처가 필요합니다")
    if item.get("connection_kind") not in {"new", "established"}:
        raise ValueError("연결 종류가 필요합니다")
    if item.get("outcome") not in OUTCOMES:
        raise ValueError("탐침 결과 오류")
    if item["outcome"] == "http":
        status = item.get("http_status")
        if scenario != "web" or type(status) is not int or not 100 <= status <= 599:
            raise ValueError("HTTP 상태 오류")
    elif scenario == "ssh" and item.get("http_status") is not None:
        raise ValueError("SSH에 HTTP 상태 사용 금지")


def probe_event(context, evidence, key, kind, probe, *, resolution="infer"):
    scenario = context["scenario"]
    outcome = "http" if "http_status" in probe else probe.get("state")
    result = event(
        context,
        evidence,
        key,
        kind,
        probe["ended_at"],
        source="tcp_probe" if scenario == "ssh" else "http_probe",
        resolution=resolution,
        outcome=outcome,
        connection_kind="new",
    )
    if "http_status" in probe:
        result["http_status"] = probe["http_status"]
    result["probe_started"] = timestamp(probe["started_at"])
    if Decimal(result["probe_started"]["epoch_seconds"]) > Decimal(result["time"]["epoch_seconds"]):
        raise ValueError("탐침 종료가 시작보다 빠릅니다")
    # 기존 elapsed_ms는 해당 탐침 프로세스의 단조 경과 시간이다. 장비 간 차로 쓰지 않는다.
    if "elapsed_ms" in probe:
        elapsed = str(probe["elapsed_ms"])
        decimal_string(elapsed)
        result["process_elapsed_ms"] = elapsed
    check_probe(result, scenario)
    return result


def runner_events(raw, context, evidence):
    lines = raw.decode("utf-8").splitlines()
    if not lines or len(lines) > MAX_EVENTS:
        raise ValueError("러너 이벤트 수 상한 위반")
    rows = []
    for line in lines:
        if len(line.encode("utf-8")) > MAX_EVENT_BYTES:
            raise ValueError("러너 행 용량 초과")
        item = strict_json(line)
        if not isinstance(item, dict):
            raise ValueError("러너 행 형식 오류")
        rows.append(item)
    starts = list({r.get("sequence"): r for r in rows if r.get("stage") == "start"}.values())
    if len(starts) != 1 or starts[0].get("details", {}).get("run_id") != context["run_id"]:
        raise ValueError("러너 실행 ID 불일치")
    selected = context["scenario"]
    mode = starts[0].get("scenario")
    if mode not in {selected, "all"}:
        raise ValueError("러너 시나리오 불일치")
    result, sequences = [], {}
    for row in rows:
        seq = row.get("sequence")
        if type(seq) is not int or not 1 <= seq <= MAX_EVENTS:
            raise ValueError("러너 순번 오류")
        if seq in sequences:
            if sequences[seq] != row:
                raise ValueError("러너 중복 순번 충돌")
        sequences[seq] = row
        if row.get("scenario") not in {selected, "all"}:
            if mode != "all":
                raise ValueError("다른 시나리오 이벤트 혼합")
            continue
        stage, details = row.get("stage"), row.get("details", {})
        recorded = row.get("recorded_at")
        timestamp(recorded)
        if "elapsed_ms" in row:
            decimal_string(str(row["elapsed_ms"]))
        if row.get("observed_at") is not None:
            timestamp(row["observed_at"])
        stamp = row.get("observed_at") or recorded
        if stage in {"baseline", "probe", "recovery_baseline"}:
            if row["scenario"] != selected:
                raise ValueError("탐침 시나리오 누락")
            item = probe_event(
                context,
                evidence,
                seq,
                "baseline" if stage == "baseline" else "probe",
                details,
                resolution=None,
            )
            if row.get("observed_at") is not None and seconds(item) != Decimal(
                timestamp(row["observed_at"])["epoch_seconds"]
            ):
                raise ValueError("러너 관측 시각과 탐침 원본 불일치")
            if stage == "probe" and details.get("within_observation_window") is False:
                continue
        elif stage == "attack_started" and row["scenario"] == selected:
            item = event(
                context,
                evidence,
                seq,
                "attack_invoked",
                stamp,
                source="runner",
                resolution=None,
                invocation_boundary="after_process_start"
                if selected == "web"
                else "before_process_start",
            )
        elif stage == "recovery_attested":
            item = event(context, evidence, seq, stage, stamp, source="operator", resolution=None)
        elif stage == "end":
            code = details.get("exit_code")
            if type(code) is not int:
                raise ValueError("러너 종료 상태 오류")
            item = event(
                context,
                evidence,
                seq,
                "observation_ended",
                stamp,
                source="runner",
                resolution=None,
                exit_code=code,
            )
        else:
            continue
        item["recorded_at"] = recorded
        item["input_sequence"] = seq
        item["runner_process_elapsed_ms"] = (
            None if "elapsed_ms" not in row else str(row["elapsed_ms"])
        )
        result.append(item)
    sequenced = sorted(sequences.values(), key=lambda r: r["sequence"])
    elapsed = [decimal_string(str(r["elapsed_ms"])) for r in sequenced if "elapsed_ms" in r]
    if any(a > b for a, b in zip(elapsed, elapsed[1:], strict=False)):
        raise ValueError("러너 단조 경과 시간 역전")
    return result


def ssh_manifest(raw, context, evidence):
    data = strict_json(raw)
    if context["scenario"] != "ssh" or data.get("schema") != "cloudshield-p3-3-private-evidence-v1":
        raise ValueError("SSH manifest 형식 오류")
    identifier(evidence.get("source_run_id"))
    if data.get("run_id") != evidence.get("source_run_id") or data.get("port") != 22:
        raise ValueError("SSH 하위 실행 또는 포트 불일치")
    if data.get("target") != "TARGET_EC2_PUBLIC_IP":
        raise ValueError("SSH 타깃 계약 오류")
    probes = data.get("probes")
    if not isinstance(probes, list) or len(probes) > MAX_ROWS:
        raise ValueError("SSH 탐침 수 오류")
    result = [probe_event(context, evidence, "baseline", "baseline", data["baseline"])]
    result.append(
        event(
            context,
            evidence,
            "hydra.started_at",
            "attack_invoked",
            data["hydra"]["started_at"],
            source="runner",
            invocation_boundary="before_process_start",
        )
    )
    result.extend(
        probe_event(context, evidence, f"probes/{n}", "probe", p) for n, p in enumerate(probes)
    )
    result.append(
        event(
            context,
            evidence,
            "ended_at",
            "observation_ended",
            data["ended_at"],
            source="runner",
            interrupted=data.get("interrupted", False),
        )
    )
    lower = Decimal(timestamp(data["started_at"])["epoch_seconds"])
    upper = Decimal(timestamp(data["ended_at"])["epoch_seconds"])
    if lower > upper or any(not lower <= seconds(i) <= upper for i in result):
        raise ValueError("SSH manifest 관측 범위·사건 시각 모순")
    return result


def web_scan(raw, context, evidence):
    if context["scenario"] != "web":
        raise ValueError("Web 증거 시나리오 불일치")
    fields = {}
    for line in raw.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in fields:
            raise ValueError("Web 요약 필드 오류 또는 실행 append 혼합")
        fields[key] = value
    if fields.get("tool") != "curl" or fields.get("target") != context.get("target_origin"):
        raise ValueError("Web 도구 또는 타깃 불일치")
    count = fields.get("attempted_requests", "")
    if not re.fullmatch(r"[0-9]{1,2}", count) or not 0 <= int(count) <= 20:
        raise ValueError("Web 요청 수 오류")
    for key in fields:
        match = re.fullmatch(r"request_([0-9]+)_.*", key)
        if match and not 1 <= int(match.group(1)) <= int(count):
            raise ValueError("Web 요청 순번·건수 불일치")
    result = []
    for n in range(1, int(count) + 1):
        prefix = f"request_{n}"
        started, ended = fields.get(prefix + "_started_at"), fields.get(prefix + "_observed_at")
        status, code = fields.get(prefix + "_http_status"), fields.get(prefix + "_exit_code")
        if started not in {None, "unknown"}:
            result.append(
                event(
                    context,
                    evidence,
                    prefix + "/invoked",
                    "attack_invoked",
                    started,
                    source="http_request",
                    invocation_boundary="before_request_call",
                )
            )
        if code == "0":
            if not isinstance(status, str) or not re.fullmatch(r"[1-5][0-9]{2}", status):
                raise ValueError("Web 요청 상태 오류")
            # 스캔 후보 404는 정상 baseline이 아니다. 통신 회복은 동일 루트 탐침만 평가한다.
            item = probe_event(
                context,
                evidence,
                prefix,
                "probe",
                {"started_at": started, "ended_at": ended, "http_status": int(status)},
            )
            item["scan_request"] = True
            result.append(item)
        elif code not in {None, "unknown"}:
            if not re.fullmatch(r"[0-9]{1,3}", code):
                raise ValueError("Web 요청 종료 코드 오류")
    if fields.get("state") == "completed" and fields.get("exit_code") != "0":
        raise ValueError("Web 완료 상태 모순")
    result.append(
        event(
            context,
            evidence,
            "ended_at",
            "observation_ended",
            fields["ended_at"],
            source="runner",
            interrupted=fields.get("state") != "completed",
        )
    )
    return result


def packet_events(raw, context, evidence):
    """기존 TCP CSV 분석기에 위임한다. SSH exporter의 flags 열만 같은 필드로 투영한다.

    공격 스트림·방향은 실행별 연결 manifest가 지정해야 한다. 가장 이른 SYN을 임의로
    공격으로 선택하지 않으며 HTTP 요청·응답 및 SYN 무응답 원인은 자동 판정하지 않는다.
    """
    text = raw.decode("utf-8")
    rows = list(csv.DictReader(io.StringIO(text)))
    if len(rows) > MAX_ROWS or not rows:
        raise ValueError("TCP CSV 행 수 오류")
    if tuple(rows[0]) != FIELDS:
        ssh_fields = (
            "frame.number",
            "frame.time_epoch",
            "tcp.stream",
            "ip.src",
            "tcp.srcport",
            "ip.dst",
            "tcp.dstport",
            "tcp.flags",
            "tcp.seq",
            "tcp.ack",
            "tcp.analysis.retransmission",
        )
        if tuple(rows[0]) != ssh_fields:
            raise ValueError("지원 TCP CSV 필드 불일치")
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()
        for row in rows:
            if None in row or any(v is None for v in row.values()):
                raise ValueError("TCP CSV 행 손상")
            if not re.fullmatch(r"0x[0-9a-fA-F]{1,4}", row["tcp.flags"]):
                raise ValueError("TCP flags 표기 오류")
            flags = int(row["tcp.flags"], 16)
            projected = {key: row[key] for key in FIELDS[:6]}
            projected.update(
                {
                    key: str(int(bool(flags & mask)))
                    for key, mask in zip(FIELDS[6:], (2, 16, 1, 4), strict=True)
                }
            )
            writer.writerow(projected)
        text = output.getvalue()
    analysis = analyze_csv(text, start=evidence["start_epoch"], end=evidence["end_epoch"])
    result = []
    if context["scenario"] == "web" and evidence.get("attack_streams"):
        raise ValueError("Web 첫 HTTP 요청에는 별도 요청 관측 좌표가 필요합니다")
    for binding in evidence.get("attack_streams", []):
        stream = str(binding["stream"])
        entry = analysis["streams"].get(stream)
        if entry is None:
            raise ValueError("지정 공격 스트림 없음")
        sender, receiver = binding["source"], binding["destination"]
        source_ip = str(ipaddress.IPv4Address(context["source_ip"]))
        target_ips = [str(ipaddress.IPv4Address(ip)) for ip in context["target_ips"]]
        port = "22" if context["scenario"] == "ssh" else "80"
        if sender.rsplit(":", 1)[0] != source_ip or receiver.rsplit(":", 1)[0] not in target_ips:
            raise ValueError("공격 패킷 출발지·타깃 불일치")
        if receiver.rsplit(":", 1)[-1] != port:
            raise ValueError("공격 패킷 서비스 포트 불일치")
        if sorted([sender, receiver]) != entry["endpoints"]:
            raise ValueError("공격 스트림 대상·방향 불일치")
        candidates = [
            p
            for p in entry["packets"]
            if p["source"] == sender and p["destination"] == receiver and p["flags"] == ["SYN"]
        ]
        if not candidates:
            raise ValueError("공격 스트림 최초 SYN 미확보")
        result.append(
            event(
                context,
                evidence,
                "stream/" + stream,
                "first_attack",
                candidates[0]["epoch"],
                source="pcap_tcp",
                packet_role="attack_connection_syn",
            )
        )
    return result


def observations(raw, context, evidence):
    data = strict_json(raw)
    for name in ("run_id", "scenario", "target_key"):
        if data.get(name) != context[name]:
            raise ValueError("관측 sidecar 실행·대상·시나리오 불일치")
    rows = data.get("events")
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("관측 이벤트 수 오류")
    result = []
    for row in rows:
        for name in ("run_id", "scenario", "target_key"):
            if name in row and row[name] != context[name]:
                raise ValueError("개별 사건 실행·대상·시나리오 불일치")
        key = identifier(row["event_id"])
        item = event(
            context,
            evidence,
            key,
            row["kind"],
            row["time"],
            source=row["source_kind"],
            resolution=row.get("resolution_seconds", "infer"),
        )
        if not isinstance(row.get("locator"), str) or not 1 <= len(row["locator"]) <= 200:
            raise ValueError("관측 원본 좌표 필요")
        backing = identifier(row.get("backing_evidence_id"))
        item["source"].update(backing_evidence_id=backing, original_locator=row["locator"])
        for name in ("outcome", "http_status", "connection_kind", "incident_id", "interrupted"):
            if name in row:
                item[name] = row[name]
        if "interrupted" in item and type(item["interrupted"]) is not bool:
            raise ValueError("중단 상태는 boolean이어야 합니다")
        if "invocation_boundary" in row:
            if (
                row["invocation_boundary"]
                not in {"before_process_start", "before_request_call", "after_process_start"}
                or item["kind"] != "attack_invoked"
            ):
                raise ValueError("호출 경계 형식 오류")
            item["invocation_boundary"] = row["invocation_boundary"]
        if item["kind"] in {"baseline", "probe"}:
            check_probe(item, context["scenario"])
        if item["kind"] == "first_attack" and item["source"]["kind"] not in {
            "pcap_tcp",
            "pcap_http",
            "http_request",
        }:
            raise ValueError("실제 공격 시각에는 직접 관측 근거가 필요합니다")
        if (
            item["kind"] == "first_attack"
            and context["scenario"] == "ssh"
            and item["source"]["kind"] != "pcap_tcp"
        ):
            raise ValueError("SSH 첫 공격에는 패킷 관측이 필요합니다")
        if (
            item["kind"] == "first_attack"
            and context["scenario"] == "web"
            and item["source"]["kind"] == "pcap_tcp"
        ):
            raise ValueError("Web TCP SYN은 첫 HTTP 요청이 아닙니다")
        if (
            item["kind"]
            in {
                "recovery_requested",
                "recovery_started",
                "recovery_api_completed",
                "configuration_verified",
            }
            and item["source"]["kind"] != "cloud_a"
        ):
            raise ValueError("복구 제어 사건에는 A 출처가 필요합니다")
        if item["kind"] == "waf_block" and item["source"]["kind"] not in {"cloud_a", "cloud_b"}:
            raise ValueError("WAF BLOCK 원본 출처 필요")
        if item["kind"] == "recovery_attested" and item["source"]["kind"] != "operator":
            raise ValueError("운영자 확인 출처 오류")
        result.append(item)
    return result


def normal(item, scenario):
    # SSH는 신규 연결 결과, Web은 TCP 재사용 여부와 독립된 HTTP 응답이 관측 단위다.
    # 스캔 후보 경로의 응답은 같은 루트 탐침의 상태 전이로 합치지 않는다.
    if item.get("scan_request"):
        return False
    if scenario == "ssh":
        return item.get("connection_kind") == "new" and item.get("outcome") == "connected"
    return item.get("outcome") == "http" and item.get("http_status") == 200


def candidate(item, scenario):
    if item.get("scan_request"):
        return False
    if scenario == "ssh":
        return item.get("connection_kind") == "new" and item.get("outcome") == "timeout"
    return item.get("outcome") == "http" and item.get("http_status") == 403


def seconds(item):
    return Decimal(item["time"]["epoch_seconds"])


def duration(start, end, clocks):
    if start is None or end is None:
        return {
            "seconds": None,
            "reason": "endpoint_not_observed",
            "start_event_id": None if start is None else start["event_id"],
            "end_event_id": None if end is None else end["event_id"],
        }
    value = seconds(end) - seconds(start)
    if value < 0:
        raise ValueError("시간 순서 모순: 음수 지연")
    same = start["clock_id"] == end["clock_id"]
    errors = [clocks[i["clock_id"]]["max_error_seconds"] for i in (start, end)]
    uncertainty = (
        None
        if any(e is None for e in errors)
        else format(sum((decimal_string(e) for e in errors), Decimal(0)), "f")
    )
    return {
        "seconds": format(value, "f"),
        "reason": None,
        "start_event_id": start["event_id"],
        "end_event_id": end["event_id"],
        "basis": "same_clock_wall_time" if same else "cross_device_wall_time",
        "clock_error_bound_seconds": uncertainty,
        "accuracy": "clock_error_unknown" if uncertainty is None else "declared_clock_bound",
        "endpoint_resolution_seconds": [i["time"]["resolution_seconds"] for i in (start, end)],
    }


def summarize(context, events, evidence):
    """원래 사건 시각으로 평가하며 파일 내 기록 순서·출처를 보존한다.

    timeout/403은 후보일 뿐 정책 집행 확정이 아니다. 같은 시각의 상반된 탐침은
    순서를 발명하지 않고 거부한다. 누락은 허용하지만 상충한 ID와 사건 연결은 거부한다.
    """
    identities, unique, duplicates = {}, [], 0
    for item in events:
        if item["event_id"] in identities:
            if identities[item["event_id"]] != item:
                raise ValueError("중복 이벤트 ID 충돌")
            duplicates += 1
            continue
        identities[item["event_id"]] = item
        unique.append(item)
    if len(events) > MAX_ROWS:
        raise ValueError("전체 이벤트 수 상한 초과")
    ordered = sorted(unique, key=lambda i: (seconds(i), i["event_id"]))
    probes = [i for i in ordered if i["kind"] in {"baseline", "probe"}]
    scenario = context["scenario"]
    simultaneous = {}
    for item in probes:
        pair = simultaneous.setdefault(seconds(item), set())
        if normal(item, scenario):
            pair.add("normal")
        if candidate(item, scenario):
            pair.add("candidate")
        if len(pair) > 1:
            raise ValueError("동일 시각 정상·차단 후보의 순서 모호")

    def first(kind):
        return next((i for i in ordered if i["kind"] == kind), None)

    attack, invoked = first("first_attack"), first("attack_invoked")
    if (
        attack
        and invoked
        and invoked.get("invocation_boundary") in {"before_process_start", "before_request_call"}
        and seconds(attack) < seconds(invoked)
    ):
        raise ValueError("실제 공격이 호출보다 빠릅니다")
    block = next((i for i in probes if candidate(i, scenario)), None)
    if block and attack and seconds(block) < seconds(attack):
        raise ValueError("차단 후보가 첫 공격보다 빠릅니다")
    baselines = [i for i in probes if i["kind"] == "baseline" and normal(i, scenario)]
    baseline = next(
        (
            i
            for i in baselines
            if ((attack or invoked) is None or seconds(i) <= seconds(attack or invoked))
            and (block is None or seconds(i) < seconds(block))
        ),
        None,
    )
    if block and not baseline:
        # 실패 표본은 보존하지만 정상→차단 전환이 입증되지 않아 구간 지연에는 쓰지 않는다.
        block = None
    last_good = next(
        (
            i
            for i in reversed(probes)
            if normal(i, scenario) and block and seconds(i) < seconds(block)
        ),
        None,
    )
    recovery = next(
        (i for i in probes if normal(i, scenario) and block and seconds(i) > seconds(block)), None
    )
    requested, started, api, configured = (
        first(k)
        for k in (
            "recovery_requested",
            "recovery_started",
            "recovery_api_completed",
            "configuration_verified",
        )
    )
    control = [i for i in (requested, started, api, configured) if i]
    if any(seconds(a) > seconds(b) for a, b in zip(control, control[1:], strict=False)):
        raise ValueError("복구 제어 사건 순서 모순")
    if started and block and seconds(started) < seconds(block):
        raise ValueError("복구 시작이 차단 후보보다 빠릅니다")
    if recovery and started and seconds(recovery) < seconds(started):
        raise ValueError("통신 회복이 복구 시작보다 빠릅니다")
    incident = context.get("incident_id")
    linked = False
    for item in ordered:
        found = item.get("incident_id")
        if found is not None:
            identifier(found)
            if found != incident:
                raise ValueError("사건 ID 불일치 또는 명시적 연결 누락")
            linked |= item["source"]["kind"] in {"cloud_a", "cloud_b"}
    refs = {e["evidence_id"]: e for e in evidence}
    for item in ordered:
        backing = item["source"].get("backing_evidence_id")
        if backing and (backing not in refs or backing == item["source"]["evidence_id"]):
            raise ValueError("원본 증거 참조 누락")
    limits = context["measurement_limits"]
    return {
        "schema_version": OUTPUT_SCHEMA,
        "run_id": context["run_id"],
        "scenario": scenario,
        "target_key": context["target_key"],
        "incident_id": incident,
        "correlation": {
            "status": "linked" if linked else "unlinked" if incident is None else "unverified",
            "basis": "supplied_evidence_binding" if linked else None,
        },
        "timeline": ordered,
        "observations": {
            "attack_invoked": invoked,
            "first_attack": attack,
            "baseline": baseline,
            "last_normal_before_candidate": last_good,
            "first_block_candidate": block,
            "recovery_requested": requested,
            "recovery_started": started,
            "recovery_api_completed": api,
            "configuration_verified": configured,
            "first_normal_after_block": recovery,
        },
        "durations": {
            "block_observation": duration(attack, block, context["clocks"]),
            "block_hold_observation": duration(block, recovery, context["clocks"]),
            "recovery_processing_observation": duration(started, recovery, context["clocks"]),
        },
        "stage_status": {
            "block": "candidate_observed" if block else "not_observed",
            "block_reason": None
            if block
            else "normal_baseline_not_observed"
            if not baseline
            else "timeout_or_403_not_observed",
            "recovery": "communication_observed" if recovery else "not_observed",
            "baseline_reason": None if baseline else "normal_baseline_not_observed",
            "attack_reason": None if attack else "actual_attack_not_observed",
            "recovery_reason": None if recovery else "normal_after_block_not_observed",
            "recovery_start_reason": None if started else "cloud_a_start_not_provided",
            "observation_complete": any(i["kind"] == "observation_ended" for i in ordered),
            "interrupted": any(i.get("interrupted") or i.get("exit_code", 0) != 0 for i in ordered),
            "configuration_restored": "evidence_provided" if configured else "not_verified",
            "idempotency": "not_evaluated",
            "policy_cause": "not_confirmed",
            "sla": "not_evaluated",
        },
        "measurement_limits": {
            key: limits[key] for key in ("probe_interval_seconds", "probe_timeout_seconds")
        },
        "clocks": {
            key: {"max_error_seconds": value["max_error_seconds"]}
            for key, value in context["clocks"].items()
        },
        "evidence": evidence,
        "integrity": {
            "duplicate_event_count": duplicates,
            "input_out_of_order": any(
                seconds(a) > seconds(b) for a, b in zip(unique, unique[1:], strict=False)
            ),
        },
    }


def build_summary(manifest: Path):
    raw = read_bounded(manifest)
    context = strict_json(raw)
    if not isinstance(context, dict) or context.get("schema_version") != INPUT_SCHEMA:
        raise ValueError("입력 manifest 버전 오류")
    for name in ("run_id", "target_key"):
        identifier(context.get(name))
    if context.get("scenario") not in {"ssh", "web"}:
        raise ValueError("단일 시나리오 필요")
    if context.get("incident_id") is not None:
        identifier(context["incident_id"])
    clocks = context.get("clocks")
    if not isinstance(clocks, dict) or not 1 <= len(clocks) <= MAX_FILES:
        raise ValueError("시계 출처 필요")
    for clock, details in clocks.items():
        identifier(clock)
        error = details.get("max_error_seconds")
        if "max_error_seconds" not in details or (error is not None and decimal_string(error) > 5):
            raise ValueError("시계 오차는 미측정 null 또는 0..5초 문자열 필요")
    limits = context.get("measurement_limits")
    if not isinstance(limits, dict):
        raise ValueError("측정 한계 필요")
    for key in ("probe_interval_seconds", "probe_timeout_seconds"):
        if key not in limits or (limits[key] is not None and decimal_string(limits[key]) <= 0):
            raise ValueError("탐침 한계는 null 또는 양수 문자열 필요")
    inputs = context.get("evidence")
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= MAX_FILES:
        raise ValueError("증거 파일 수 상한 위반")
    events, records, names, paths, loaded = [], [], set(), set(), []
    adapters = {
        "runner_events": runner_events,
        "ssh_manifest": ssh_manifest,
        "web_scan": web_scan,
        "tcp_csv": packet_events,
        "observations": observations,
    }
    for entry in inputs:
        name = identifier(entry.get("evidence_id"))
        if name in names or entry.get("format") not in FORMATS:
            raise ValueError("중복 증거 ID 또는 형식 오류")
        names.add(name)
        for key in ("run_id", "scenario", "target_key"):
            if entry.get(key) != context[key]:
                raise ValueError("증거 실행·대상·시나리오 불일치")
        if entry.get("clock_id") not in clocks:
            raise ValueError("증거 시계 출처 불명")
        path = Path(entry["path"])
        path = path if path.is_absolute() else manifest.parent / path
        resolved = path.resolve(strict=True)
        if resolved in paths:
            raise ValueError("동일 증거 파일 중복 등록")
        paths.add(resolved)
        info, content = fingerprint(path, entry["sha256"])
        records.append(
            {
                "evidence_id": name,
                "format": entry["format"],
                **info,
                "source_run_id": entry.get("source_run_id"),
                "binding": "declared_by_input_manifest",
            }
        )
        if entry["format"] != "opaque":
            if content is None:
                raise ValueError("메타데이터 입력 1MiB 초과")
            events.extend(adapters[entry["format"]](content, context, entry))
            loaded.append((entry, content))
    # 상위 러너가 기록한 하위 실행 ID/manifest 해시가 있으면 선언값보다 우선 검증한다.
    children = {}
    for entry, content in loaded:
        if entry["format"] == "runner_events":
            for line in content.decode("utf-8").splitlines():
                row = strict_json(line)
                if row.get("scenario") == "ssh" and row.get("stage") == "attack_finished":
                    details = row.get("details", {})
                    children[details.get("run_id")] = details.get("manifest_sha256")
    for entry, content in loaded:
        if entry["format"] == "ssh_manifest":
            if children and children.get(entry["source_run_id"]) != entry["sha256"]:
                raise ValueError("상위 러너와 하위 SSH manifest 연결 불일치")
            data = strict_json(content)
            for original in inputs:
                name = Path(original["path"]).name
                expected = data.get("evidence", {}).get(name)
                if expected and expected.get("sha256") != original["sha256"]:
                    raise ValueError("SSH manifest의 원본 증거 해시 불일치")
    result = summarize(context, events, records)
    result["input_manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    return result


def write_summary(source: Path, output: Path):
    """동일 디렉터리 임시 파일에 완성한 뒤 hard link로 독점 게시한다.

    Why: x 모드의 최종 파일에 직접 쓰면 실패한 부분 JSON이 정상 요약처럼 노출된다.
    Constraints: 로컬 hard-link 지원 파일시스템. 미지원 시 덮어쓰기 방식으로 폴백하지 않는다.
    Side-effects: 임시 파일만 정리한다. 기존 출력은 보존하며 게시/동기화 실패는 예외 전파한다.
    """
    result = build_summary(source)
    payload = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(payload) > MAX_BYTES * 8:
        raise ValueError("요약 출력 용량 초과")
    descriptor, temporary = tempfile.mkstemp(prefix=".roundtrip-", suffix=".tmp", dir=output.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, output)
    finally:
        Path(temporary).unlink()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        write_summary(args.manifest, args.output)
    except (
        OSError,
        ValueError,
        UnicodeError,
        KeyError,
        TypeError,
        AttributeError,
        RecursionError,
        OverflowError,
        csv.Error,
    ):
        parser.exit(2, "요약 실패: 입력 연결·시각·해시·상한·새 출력 경로를 확인하세요\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
