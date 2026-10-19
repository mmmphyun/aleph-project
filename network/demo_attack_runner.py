#!/usr/bin/env python3
"""기존 유한 공격 도구를 연결하고 로컬 관측만 기록하는 발표용 러너.

Why: 공격·탐지·AWS 복구를 재구현하지 않고 네트워크 담당의 실행 경계와 증거를 통합한다.
Constraints: 기본 dry-run, 현재 승인된 단일 대상, 한 번의 공격, 최대 60초 Web 관측.
Side-effects: --execute는 실제 통신을 한다. 승인·원본 증거는 Git 밖에만 두며 AWS API는 없다.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import ec2_hydra_measurement as ssh

DIRECTORY = Path(__file__).resolve().parent
MAX_APPROVAL_BYTES = 16384
MAX_EVENTS = 512
MAX_EVENT_BYTES = 4096
MAX_EVIDENCE_BYTES = 1024 * 1024
WEB_CANDIDATES = 15
WEB_SECONDS = 60
# 과거 일회용 공격 노드의 출발 주소다. 승인 파일에 잘못 복사돼도 EC2 타깃으로 쓰지 않는다.
FORMER_ATTACK_NODES = frozenset({"3.26.171.60"})


class RunnerError(RuntimeError):
    """공유 가능한 진단과 비정상 종료 코드를 함께 전달한다."""

    def __init__(self, message: str, code: int = 2) -> None:
        super().__init__(message)
        self.code = code


class RunnerSignal(BaseException):
    """SIGTERM도 기존 계측기의 BaseException 정리 경로를 통과시킨다."""

    def __init__(self, code: int) -> None:
        self.code = code


@dataclass(frozen=True, repr=False)
class Approval:
    approval_id: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    source_ipv4: str
    ec2_ip: str | None
    instance_id: str | None
    alb_origin: str | None

    def require_current(self, now: datetime | None = None) -> None:
        stamp = datetime.now(UTC) if now is None else now
        if not self.approved_at <= stamp < self.expires_at:
            raise RunnerError("현재 시각에 유효한 대상 승인이 필요합니다.")


def bounded_seconds(value: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]?", value) or not 1 <= int(value) <= WEB_SECONDS:
        raise argparse.ArgumentTypeError("관측 제한은 1..60초입니다.")
    return int(value)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--scenario", choices=("ssh", "web", "all"), default="all")
    mode = result.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    result.add_argument("--approval-file", type=Path)
    result.add_argument("--evidence-root", type=Path)
    result.add_argument("--interface", default="eth0")
    result.add_argument("--web-observe-seconds", type=bounded_seconds, default=60)
    return result


def approved_alb_host() -> str:
    """호스트 허용 목록은 기존 스캐너의 단일 계약에서 읽는다. DNS 조회는 하지 않는다."""
    source = (DIRECTORY / "web_dir_scan.sh").read_text(encoding="utf-8")
    matches = re.findall(r"^readonly APPROVED_ALB_HOST='([a-z0-9.-]+)'$", source, re.M)
    if len(matches) != 1:
        raise RunnerError("기존 Web 스캐너의 승인 호스트 계약을 확인할 수 없습니다.")
    return matches[0]


def validate_origin(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 128:
        raise RunnerError("승인 ALB origin 형식 오류입니다.")
    host = approved_alb_host()
    # URL 전체 일치를 먼저 요구하므로 userinfo·쿼리·fragment·리다이렉트 대상은 승인할 수 없다.
    if value.lower() not in (
        f"http://{host}",
        f"http://{host}/",
        f"http://{host}:80",
        f"http://{host}:80/",
    ):
        raise RunnerError("기존 스캐너가 허용한 ALB HTTP 80만 실행할 수 있습니다.")
    parsed = urlsplit(value)
    return f"http://{parsed.hostname}"


def approval_time(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise RunnerError("승인 시각에는 UTC ISO 8601 값이 필요합니다.")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RunnerError("승인 시각 형식 오류입니다.") from None
    if stamp.utcoffset() != timedelta(0):
        raise RunnerError("승인 시각은 UTC여야 합니다.")
    return stamp


def parse_approval(data: Any, scenario: str, *, now: datetime | None = None) -> Approval:
    """승인 자료를 형식·유효기간·실제 자산 식별자로 묶는다. AWS 소유권 조회를 대신하지 않는다."""
    if not isinstance(data, dict):
        raise RunnerError("승인 파일에는 JSON 객체가 필요합니다.")
    for name in ("approval_id", "approved_by"):
        if not isinstance(data.get(name), str) or not re.fullmatch(
            r"[A-Za-z0-9_.@/-]{1,80}", data[name]
        ):
            raise RunnerError("승인 식별자와 담당자 기록이 필요합니다.")
    start, end = (approval_time(data.get(name)) for name in ("approved_at", "expires_at"))
    if not timedelta(0) < end - start <= timedelta(hours=24):
        raise RunnerError("대상 승인은 최대 24시간의 유한 구간이어야 합니다.")
    try:
        source = ssh.validate_public_ipv4(data.get("source_ipv4", ""))
        ec2 = data.get("ec2", {})
        ip = ssh.validate_public_ipv4(ec2.get("public_ip", "")) if scenario != "web" else None
    except (ssh.PreparationError, TypeError, AttributeError):
        raise RunnerError("승인된 출발 IP와 필요한 EC2 공개 IPv4가 필요합니다.") from None
    instance = ec2.get("instance_id") if scenario != "web" else None
    if scenario != "web" and (
        not isinstance(instance, str)
        or not re.fullmatch(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})", instance)
        or ip == source
        or ip in FORMER_ATTACK_NODES
    ):
        raise RunnerError("EC2 인스턴스 식별자와 출발지와 다른 승인 타깃이 필요합니다.")
    origin = validate_origin(data.get("alb_origin")) if scenario != "ssh" else None
    approval = Approval(
        data["approval_id"], data["approved_by"], start, end, source, ip, instance, origin
    )
    approval.require_current(now)
    return approval


def private_root(path: Path | None) -> Path:
    if path is None or any(ord(char) < 32 for char in str(path)):
        raise RunnerError("Git 밖의 비공개 절대 경로가 필요합니다.")
    try:
        return ssh.validate_evidence_root(str(path))
    except ssh.PreparationError:
        raise RunnerError("Linux의 소유자 전용 0700 디렉터리를 Git 밖에 준비하세요.") from None


def load_approval(path: Path | None, scenario: str) -> Approval:
    if path is None or not path.is_absolute() or path.is_symlink():
        raise RunnerError("현재 승인을 담은 비공개 승인 파일이 필요합니다.")
    parent = private_root(path.parent)
    if path.parent != parent:
        raise RunnerError("승인 파일 경로에 심볼릭 링크를 사용할 수 없습니다.")
    # O_NOFOLLOW와 열린 FD의 속성을 검사해 링크 교체나 과도한 입력을 읽기 전에 차단한다.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RunnerError("승인 파일은 실행 사용자 소유의 0600 일반 파일이어야 합니다.")
        raw = stream.read(MAX_APPROVAL_BYTES + 1)
    if len(raw) > MAX_APPROVAL_BYTES:
        raise RunnerError("승인 파일은 16KiB를 초과할 수 없습니다.")
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        raise RunnerError("승인 파일의 JSON 형식 오류입니다.") from None
    return parse_approval(data, scenario)


class Reporter:
    """실행 순번과 원래 관측 시각을 함께 기록한다. 저장 실패는 stdout 성공으로 숨기지 않는다."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory
        self.started = time.monotonic()
        self.count = 0
        self.bytes = 0
        self.stream = (
            (directory / "events.jsonl").open("x", encoding="utf-8") if directory else None
        )
        print("| UTC | 시나리오 | 단계 | 관측 결과 | 남은 관측 시간(s) |", flush=True)
        print("| --- | --- | --- | --- | ---: |", flush=True)

    def emit(
        self,
        scenario: str,
        stage: str,
        result: str,
        *,
        stamp: str | None = None,
        remaining: float | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        if stamp is not None:
            try:
                observed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                raise RunnerError("관측 시각 형식 오류입니다.", 70) from None
            if observed.utcoffset() != timedelta(0):
                raise RunnerError("관측 시각은 UTC여야 합니다.", 70)
            stamp = observed.isoformat(timespec="milliseconds")
        elapsed = time.monotonic() - self.started
        if elapsed < 0 or not math.isfinite(elapsed):
            raise RunnerError("단조 시계가 유효하지 않습니다.", 70)
        record = {
            "sequence": self.count + 1,
            "recorded_at": ssh.utc_now(),
            "observed_at": stamp,
            "elapsed_ms": round(elapsed * 1000, 3),
            "scenario": scenario,
            "stage": stage,
            "result": result,
            "remaining_seconds": None if remaining is None else round(max(0, remaining), 3),
            "details": details or {},
        }
        line = json.dumps(record, ensure_ascii=False) + "\n"
        size = len(line.encode("utf-8"))
        if (
            self.count >= MAX_EVENTS
            or size > MAX_EVENT_BYTES
            or self.bytes + size > MAX_EVIDENCE_BYTES
        ):
            raise RunnerError("실행 메타데이터 저장 상한을 초과했습니다.", 74)
        if self.stream is not None:
            self.stream.write(line)
            self.stream.flush()
        self.count += 1
        self.bytes += size
        safe_result = result.replace("|", "/").replace("\n", " ").replace("\r", " ")
        countdown = "-" if remaining is None else f"{max(0, remaining):.1f}"
        print(
            f"| {stamp or record['recorded_at']} | {scenario} | {stage} | "
            f"{safe_result} | {countdown} |",
            flush=True,
        )

    def close(self) -> None:
        if self.stream is not None:
            self.stream.close()


def create_run_directory(root: Path, *, run_id: str | None = None) -> Path:
    name = run_id or datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(6)
    if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", name):
        raise RunnerError("실행 식별자 형식 오류입니다.")
    directory = root / name
    directory.mkdir(mode=0o700, exist_ok=False)
    return directory


def run_ssh(
    args: argparse.Namespace,
    approval: Approval,
    directory: Path,
    report: Reporter,
    environ: dict[str, str],
) -> str:
    approval.require_current()
    if environ.get("CLOUDSHIELD_TARGET_IP") != approval.ec2_ip:
        raise RunnerError("SSH 환경 타깃과 현재 승인된 EC2가 일치해야 합니다.")
    root = directory / "ssh"
    root.mkdir(mode=0o700)
    config_args = argparse.Namespace(interface=args.interface, evidence_root=str(root))
    config = ssh.load_config(config_args, environ)
    first_candidate = False
    probe_error = False

    def observe(stage: str, event: dict[str, Any]) -> None:
        nonlocal first_candidate, probe_error
        stamp = event.get("ended_at", event.get("started_at"))
        remaining = event.get("remaining_seconds")
        result = str(event.get("state", ""))
        if stage == "attack_started":
            result = "Hydra 호출 경계; 실제 첫 SYN·서버 인증 실패 시각은 별도 증거 필요"
        elif stage == "evidence":
            result = "비공개 캡처·계측 증거 저장 위치"
        elif stage == "countdown":
            result = "관측 상한; 차단 완료를 보장하지 않음"
        report.emit("ssh", stage, result, stamp=stamp, remaining=remaining, details=event)
        if stage == "probe" and event["state"] == "timeout" and not first_candidate:
            first_candidate = True
            report.emit(
                "ssh",
                "first_block_candidate",
                "TCP connect timeout; PCAP SYN 무응답·SG 원인은 미확정",
                stamp=stamp,
            )
        if stage == "probe" and event["state"] in {"network_error", "refused"}:
            probe_error = True

    summary = ssh.run_measurement(config, observer=observe)
    report.emit(
        "ssh", "attack_finished", "기존 계측기 완료; AWS·Slack 결과 미평가", details=summary
    )
    if probe_error:
        raise RunnerError("TCP 오류/거부가 관측되어 차단 성공으로 판정하지 않습니다.", 70)
    if not first_candidate:
        report.emit("ssh", "not_observed", "관측 제한 종료; 차단 후보 미관측")
        raise RunnerError("SSH 관측 구간에서 차단 후보를 확인하지 못했습니다.", 3)
    return "tcp_timeout_candidate"


class Children:
    """각 Popen이 생성한 세션만 추적한다. 시스템 전체 이름 검색이나 pkill은 사용하지 않는다."""

    def __init__(self) -> None:
        self.owned: list[subprocess.Popen[Any]] = []

    def start(self, argv: list[str], **kwargs: Any) -> subprocess.Popen[Any]:
        try:
            process = subprocess.Popen(argv, start_new_session=True, **kwargs)
        except OSError:
            raise RunnerError("자식 도구를 시작하지 못했습니다.", 70) from None
        self.owned.append(process)
        return process

    def cleanup(self) -> None:
        failed = False
        for process in reversed(self.owned):
            try:
                ssh.terminate_owned_process(process)
            except (OSError, subprocess.SubprocessError):
                failed = True
        if failed:
            raise RunnerError("일부 소유 자식의 종료를 확인하지 못했습니다.", 70)


def http_probe(origin: str, children: Children, *, timeout_seconds: float = 1) -> dict[str, Any]:
    """루트 HEAD 한 건만 보낸다. 본문·헤더·외부 진단은 저장하지 않고 리다이렉트를 따르지 않는다."""
    curl = ssh.require_tool("curl")
    if not math.isfinite(timeout_seconds) or not 0.001 <= timeout_seconds <= 1:
        raise RunnerError("HTTP 탐침 제한 시간 범위 오류입니다.")
    timeout_value = f"{timeout_seconds:.3f}"
    started_at, before = ssh.utc_now(), time.monotonic()
    process = children.start(
        [
            curl,
            "-q",
            "--silent",
            "--noproxy",
            "*",
            "--proxy",
            "",
            "--max-redirs",
            "0",
            "--proto",
            "=http",
            "--ipv4",
            "--head",
            "--connect-timeout",
            timeout_value,
            "--max-time",
            timeout_value,
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--",
            origin + "/",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        output, _ = process.communicate(timeout=timeout_seconds + 1)
    except subprocess.TimeoutExpired:
        ssh.terminate_owned_process(process)
        raise RunnerError("HTTP 관측 도구가 제한 시간을 초과했습니다.", 124) from None
    if process.returncode:
        code = 124 if process.returncode == 28 else exit_code(process.returncode)
        raise RunnerError("HTTP 관측 도구 timeout 또는 실행 오류입니다.", code)
    if not re.fullmatch(r"[1-5][0-9]{2}", output):
        raise RunnerError("HTTP 관측 도구에서 유효한 상태를 받지 못했습니다.", 70)
    return {
        "started_at": started_at,
        "ended_at": ssh.utc_now(),
        "http_status": int(output),
        "elapsed_ms": round((time.monotonic() - before) * 1000, 3),
    }


def exit_code(code: int) -> int:
    return 128 - code if code < 0 else code


def require_http_baseline(approval: Approval, children: Children, report: Reporter) -> None:
    event = http_probe(approval.alb_origin, children)
    report.emit(
        "web",
        "baseline",
        f"HEAD / HTTP {event['http_status']}",
        stamp=event["ended_at"],
        details=event,
    )
    if event["http_status"] != 200:
        raise RunnerError("공격 전 HTTP 200 baseline 미확인으로 Web 공격을 거부합니다.", 20)


def run_web(
    args: argparse.Namespace,
    approval: Approval,
    directory: Path,
    report: Reporter,
    children: Children,
) -> str:
    approval.require_current()
    require_http_baseline(approval, children, report)
    approval.require_current()
    bash = ssh.require_tool("bash")
    summary = directory / "web-scan.txt"
    before = time.monotonic()
    attack = children.start(
        [
            bash,
            str(DIRECTORY / "web_dir_scan.sh"),
            "--url",
            approval.alb_origin,
            "--tool",
            "curl",
            "--candidates",
            str(WEB_CANDIDATES),
            "--concurrency",
            "1",
            "--interval",
            "1",
            "--timeout",
            "3",
            "--max-runtime",
            str(WEB_SECONDS),
            "--evidence",
            str(summary),
            "--execute",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    report.emit(
        "web", "attack_started", "기존 Web 스캐너 1회 호출; 첫 요청 시각은 별도 증거에 기록"
    )
    deadline = before + args.web_observe_seconds
    first_candidate = False
    # 최대 60개의 관측 슬롯이며, 완료된 탐침 사이에 최소 1초 간격을 둔다.
    # 지연된 슬롯을 몰아 보내지 않고 단조 deadline에서 관측을 끝낸다.
    next_probe = before
    for _ in range(args.web_observe_seconds):
        scheduled = min(next_probe, deadline)
        while time.monotonic() < scheduled:
            code = attack.poll()
            if code not in (None, 0):
                raise RunnerError("Web 공격 도구가 실패했습니다.", exit_code(code))
            time.sleep(max(0, min(0.05, scheduled - time.monotonic())))
        remaining = deadline - time.monotonic()
        if remaining < 0.001:
            break
        code = attack.poll()
        if code not in (None, 0):
            raise RunnerError("Web 공격 도구가 실패했습니다.", exit_code(code))
        report.emit(
            "web",
            "countdown",
            "관측 상한; WAF 반영 완료를 보장하지 않음",
            remaining=deadline - time.monotonic(),
        )
        event = http_probe(approval.alb_origin, children, timeout_seconds=min(1, remaining))
        in_window = time.monotonic() <= deadline
        next_probe = time.monotonic() + 1
        report.emit(
            "web",
            "probe" if in_window else "late_probe",
            f"HEAD / HTTP {event['http_status']}",
            stamp=event["ended_at"],
            details=event | {"within_observation_window": in_window},
            remaining=deadline - time.monotonic(),
        )
        if event["http_status"] == 403 and in_window and not first_candidate:
            first_candidate = True
            report.emit(
                "web",
                "first_block_candidate",
                "HTTP 200 → 403 관측; WAF BLOCK 원인은 로그 대조 필요",
                stamp=event["ended_at"],
            )
        code = attack.poll()
        if code not in (None, 0):
            raise RunnerError("Web 공격 도구가 실패했습니다.", exit_code(code))
        if not in_window:
            break
        if first_candidate and code == 0:
            break
    while attack.poll() is None and time.monotonic() < deadline:
        time.sleep(max(0, min(0.05, deadline - time.monotonic())))
    if attack.poll() is None:
        raise RunnerError("Web 관측 제한 종료 시 공격 도구가 실행 중이므로 중단합니다.", 124)
    if attack.returncode != 0:
        raise RunnerError("Web 공격 도구가 실패했습니다.", exit_code(attack.returncode))
    # 종료 코드 0만 신뢰하지 않고 기존 스캐너가 생성한 제한된 요약의 완료 상태도 확인한다.
    with summary.open("rb") as stream:
        raw = stream.read(MAX_APPROVAL_BYTES + 1)
    if len(raw) > MAX_APPROVAL_BYTES:
        raise RunnerError("Web 요약 용량 초과입니다.", 74)
    fields = dict(line.split("=", 1) for line in raw.decode("utf-8").splitlines() if "=" in line)
    if fields.get("state") != "completed" or fields.get("exit_code") != "0":
        raise RunnerError("Web 스캐너 완료 증거가 없습니다.", 70)
    for index in range(1, WEB_CANDIDATES + 1):
        prefix = f"request_{index}"
        observed = fields.get(prefix + "_observed_at", "")
        status = fields.get(prefix + "_http_status", "")
        if not re.fullmatch(r"[1-5][0-9]{2}", status) or not observed:
            raise RunnerError("Web 스캐너 요청별 증거가 불완전합니다.", 70)
        report.emit(
            "web",
            "attack_request_recorded",
            f"GET 후보 {index}: HTTP {status}; 종료 후 증거 대조",
            stamp=observed,
        )
    report.emit("web", "attack_finished", "15개 후보 실행 완료; 원본 메타데이터 web-scan.txt")
    if not first_candidate:
        report.emit("web", "not_observed", "관측 제한 종료; HTTP 403 미관측", remaining=0)
        raise RunnerError("Web 관측 구간에서 차단 후보를 확인하지 못했습니다.", 3)
    return "http_403_candidate"


def confirm_recovery(run_id: str, report: Reporter) -> None:
    """각 실행의 단계 사이에서 새 확인을 받는다. 시작 전에 넣은 플래그로 복구를 대신하지 않는다."""
    report.emit(
        "all", "recovery_required", "클라우드 A의 SG/WAF 복구 완료 확인 필요; 복구 API 호출 없음"
    )
    if not sys.stdin.isatty():
        raise RunnerError(
            "순차 실행은 대화형 복구 확인이 필요합니다. 다음 공격을 시작하지 않았습니다.", 20
        )
    try:
        response = input(f"담당자 복구 확인 후 RESTORED {run_id} 입력: ")
    except EOFError:
        raise RunnerError("복구 확인이 없어 다음 공격을 시작하지 않았습니다.", 20) from None
    if response != f"RESTORED {run_id}":
        raise RunnerError("복구 확인이 일치하지 않아 다음 공격을 시작하지 않았습니다.", 20)
    report.emit(
        "all", "recovery_attested", "운영자 복구 확인; 실제 상태는 이어지는 baseline으로 재확인"
    )


def dry_run(args: argparse.Namespace) -> int:
    report = Reporter()
    report.emit(args.scenario, "start", "dry-run; 외부 통신·명령 실행·파일 생성 0건")
    if args.scenario != "web":
        report.emit(
            "ssh", "plan", "승인 EC2:22 / 합성 오답 5개 / 동시성 1 / 공격 60초 / 캡처 75초·2000패킷"
        )
    if args.scenario == "all":
        report.emit("all", "plan", "담당자 복구 확인 → TCP 정상 → HTTP 200 확인 후에만 Web 시작")
    if args.scenario != "ssh":
        report.emit(
            "web",
            "plan",
            f"승인 ALB HTTP 80 / 후보 15개 / 동시성 1 / HEAD 최대 {args.web_observe_seconds}회",
            remaining=args.web_observe_seconds,
        )
    report.emit(args.scenario, "end", "계획만 완료; AWS·WAF·Slack 결과 및 10초 SLA는 미평가")
    return 0


def execute(args: argparse.Namespace, environ: dict[str, str]) -> int:
    # 모든 준비 검증은 증거 생성·도구 조회·네트워크 호출보다 먼저 끝낸다.
    root = private_root(args.evidence_root)
    approval = load_approval(args.approval_file, args.scenario)
    if any(environ.get(name) != "yes" for name in ssh.READY_ENV):
        raise RunnerError("파이프라인·출발 IP 허용·복구 준비 확인이 모두 필요합니다.")
    if args.scenario != "web":
        if environ.get("CLOUDSHIELD_TARGET_IP") != approval.ec2_ip:
            raise RunnerError("SSH 환경 타깃과 현재 승인된 EC2가 일치해야 합니다.")
        ssh.validate_account(environ.get("CLOUDSHIELD_TEST_ACCOUNT", ""))
    directory = create_run_directory(root)
    report = Reporter(directory)
    children = Children()
    code, result = 0, "completed_with_local_candidates_only"
    previous_term = signal.getsignal(signal.SIGTERM)

    def interrupted(signum: int, _frame: Any) -> None:
        raise RunnerSignal(128 + signum)

    signal.signal(signal.SIGTERM, interrupted)
    try:
        report.emit(
            args.scenario,
            "start",
            "명시적 실행; 로컬 관측만 평가",
            details={"approval_id": approval.approval_id, "run_id": directory.name},
        )
        report.emit(args.scenario, "evidence", str(directory))
        if args.scenario != "web":
            run_ssh(args, approval, directory, report, environ)
        if args.scenario == "all":
            confirm_recovery(directory.name, report)
            approval.require_current()
            baseline = ssh.probe_once(approval.ec2_ip)
            report.emit(
                "ssh",
                "recovery_baseline",
                baseline["state"],
                stamp=baseline["ended_at"],
                details=baseline,
            )
            if baseline["state"] != "connected":
                raise RunnerError(
                    "복구 후 TCP baseline 미확인으로 다음 공격을 시작하지 않았습니다.", 20
                )
        if args.scenario != "ssh":
            run_web(args, approval, directory, report, children)
    except (RunnerError, ssh.MeasurementError) as exc:
        code, result = exc.code, str(exc)
    except ssh.PreparationError:
        code, result = 2, "기존 도구의 준비 조건 미충족"
    except KeyboardInterrupt:
        code, result = 130, "사용자 중단"
    except RunnerSignal as exc:
        code, result = exc.code, "종료 신호로 중단"
    except (OSError, UnicodeError):
        code, result = 74, "증거/로컬 입출력 오류"
    except subprocess.SubprocessError:
        code, result = 70, "자식 프로세스 오류"
    except Exception:
        # 내부 오류에도 최종 증거를 성공으로 남기지 않는다. 예외 원문은 비밀 노출을 피한다.
        code, result = 70, "러너 내부 오류; 로컬 실행 실패"
    finally:
        try:
            children.cleanup()
        except RunnerError as exc:
            code, result = exc.code, str(exc)
        finally:
            signal.signal(signal.SIGTERM, previous_term)
            try:
                report.emit(
                    args.scenario,
                    "end",
                    result,
                    details={"exit_code": code, "aws_waf_slack": "not_evaluated"},
                )
            finally:
                report.close()
    return code


def main(argv: list[str] | None = None, environ: dict[str, str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        ssh.validate_interface(args.interface)
        if not args.execute:
            return dry_run(args)
        return execute(args, dict(os.environ if environ is None else environ))
    except (RunnerError, ssh.MeasurementError) as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    except ssh.PreparationError:
        print("기존 계측기의 입력 검증에 실패했습니다.", file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("증거/승인 파일 입출력 실패; 성공으로 처리하지 않았습니다.", file=sys.stderr)
        return 74
    except subprocess.SubprocessError:
        print("도구 실행 오류입니다.", file=sys.stderr)
        return 70
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
