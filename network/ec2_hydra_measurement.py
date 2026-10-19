#!/usr/bin/env python3
"""승인된 단일 EC2의 SSH 실패와 L4 연결 변화를 제한적으로 계측한다.

Why:
    Docker 전용 Hydra 러너의 소유권 가드를 약화하지 않고 실제 EC2 실측 경로를 분리한다.
Constraints:
    공개 IPv4 한 곳, TCP 22, 전용 테스트 계정, 합성 오답 5개, 동시성 1, 실행 1회만 허용한다.
Side-effects / Edge-cases:
    ``run --execute``는 실제 SSH 인증 실패와 패킷 캡처를 발생시킨다. 원본 증거에는 실제 IP가
    포함될 수 있으므로 Git 밖 0700 디렉터리에만 기록하며, 캡처·Hydra 자식만 개별 종료한다.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PORT = 22
CANDIDATE_COUNT = 5
HYDRA_RESPONSE_SECONDS = 10
# PAM 인증 지연을 후보 실패로 오인하지 않도록 응답 대기를 확보하되 전체 실행은 제한한다.
# 후보 수·동시성은 늘리지 않으며, 시간 초과나 연결 오류는 서버 인증 실패 수로 환산하지 않는다.
HYDRA_SECONDS = 60
CAPTURE_SECONDS = 75
CAPTURE_PACKETS = 2000
PROBE_COUNT = 60
PROBE_INTERVAL_SECONDS = 1
PROBE_TIMEOUT_SECONDS = 0.8
TARGET_LABEL = "TARGET_EC2_PUBLIC_IP"
READY_ENV = (
    "CLOUDSHIELD_PIPELINE_READY",
    "CLOUDSHIELD_SOURCE_ALLOWED",
    "CLOUDSHIELD_RECOVERY_READY",
)
ACCOUNT_PATTERN = re.compile(r"cloudshield_test(?:_[a-z0-9]{1,12})?")
INTERFACE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}")


class PreparationError(RuntimeError):
    """네트워크 부작용 전에 발견한 준비 미충족을 나타낸다."""


class MeasurementError(RuntimeError):
    """실측 시작 뒤의 실패를 안전한 종료 코드와 함께 전달한다."""

    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, repr=False)
class Config:
    target: str
    account: str
    interface: str
    evidence_root: Path


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def plan() -> dict[str, Any]:
    """비공개 입력을 읽거나 외부 명령을 호출하지 않는 고정 실행 계약을 반환한다."""
    return {
        "mode": "plan",
        "network_executed": False,
        "target": TARGET_LABEL,
        "port": PORT,
        "test_account_required": True,
        "candidate_count": CANDIDATE_COUNT,
        "concurrency": 1,
        "hydra_response_timeout_seconds": HYDRA_RESPONSE_SECONDS,
        "hydra_timeout_seconds": HYDRA_SECONDS,
        "capture_seconds": CAPTURE_SECONDS,
        "capture_packet_limit": CAPTURE_PACKETS,
        "probe_count": PROBE_COUNT,
        "probe_interval_seconds": PROBE_INTERVAL_SECONDS,
        "reruns": 0,
    }


def validate_public_ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise PreparationError("승인 대상은 정규화된 공개 IPv4여야 합니다.") from exc
    if str(address) != value or not address.is_global:
        raise PreparationError(
            "사설·예약·비정규화 주소는 외부 EC2 실측 대상으로 사용할 수 없습니다."
        )
    return value


def validate_account(value: str) -> str:
    # 이름 규약 자체를 전용 계정 증거로 사용한다. root/admin/AMI 기본 계정의 우발 사용을 막는다.
    if not ACCOUNT_PATTERN.fullmatch(value):
        raise PreparationError(
            "테스트 계정은 cloudshield_test 또는 cloudshield_test_<소문자/숫자> 형식이어야 합니다."
        )
    return value


def validate_interface(value: str) -> str:
    if value == "any" or not INTERFACE_PATTERN.fullmatch(value):
        raise PreparationError("캡처 인터페이스는 any가 아닌 단일 안전 이름이어야 합니다.")
    return value


def validate_evidence_root(value: str) -> Path:
    if os.name != "posix":
        raise PreparationError("실측 실행은 Kali Linux에서만 허용합니다.")
    supplied = Path(value)
    if not supplied.is_absolute() or supplied.is_symlink():
        raise PreparationError("증거 루트는 심볼릭 링크가 아닌 절대 경로여야 합니다.")
    try:
        root = supplied.resolve(strict=True)
    except OSError as exc:
        raise PreparationError("증거 루트가 존재하지 않습니다.") from exc
    metadata = root.stat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise PreparationError("증거 루트는 접근 제한된 0700 디렉터리여야 합니다.")
    if metadata.st_uid != os.geteuid():
        raise PreparationError("증거 루트는 현재 실행 사용자가 소유해야 합니다.")
    if any((ancestor / ".git").exists() for ancestor in (root, *root.parents)):
        raise PreparationError("원본 증거는 Git 작업 트리 밖에 보존해야 합니다.")
    return root


def load_config(args: argparse.Namespace, environ: dict[str, str]) -> Config:
    missing = [name for name in READY_ENV if environ.get(name) != "yes"]
    if missing:
        raise PreparationError("파이프라인·출발 IP 허용·복구 준비 확인이 모두 필요합니다.")
    return Config(
        target=validate_public_ipv4(environ.get("CLOUDSHIELD_TARGET_IP", "")),
        account=validate_account(environ.get("CLOUDSHIELD_TEST_ACCOUNT", "")),
        interface=validate_interface(args.interface),
        evidence_root=validate_evidence_root(args.evidence_root),
    )


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise PreparationError(f"필수 도구가 없습니다: {name}")
    return path


def check_hydra(binary: str) -> str:
    result = subprocess.run([binary, "-h"], capture_output=True, text=True, timeout=5, check=False)
    output = result.stdout + result.stderr
    services = re.search(r"Supported services:\s*([^\r\n]+)", output)
    # Hydra 9.7은 도움말을 정상 출력해도 255를 반환하므로 종료 코드 대신 기능 표기를 검증한다.
    if not services or "ssh" not in services[1].split() or "-K" not in output:
        raise PreparationError("Hydra SSH 모듈 또는 -K 안전 옵션을 확인할 수 없습니다.")
    return output.splitlines()[0] if output.splitlines() else "unknown"


def tool_version(binary: str, *arguments: str) -> str:
    result = subprocess.run(
        [binary, *arguments], capture_output=True, text=True, timeout=5, check=False
    )
    lines = (result.stdout + result.stderr).splitlines()
    return lines[0] if lines else "unknown"


def create_execution_guard(root: Path) -> Path:
    guard = root / ".p3-3-executed"
    try:
        descriptor = os.open(guard, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise PreparationError(
            "이 증거 루트에서는 P3-3 실측을 이미 시작해 재실행할 수 없습니다."
        ) from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(json.dumps({"started_at": utc_now(), "reruns_allowed": 0}) + "\n")
    return guard


def build_hydra_command(binary: str, config: Config, candidates: Path) -> list[str]:
    return [
        binary,
        "-I",
        "-K",
        "-f",
        "-v",
        "-l",
        config.account,
        "-P",
        str(candidates),
        "-t",
        "1",
        "-w",
        str(HYDRA_RESPONSE_SECONDS),
        "-W",
        "1",
        "-s",
        str(PORT),
        config.target,
        "ssh",
    ]


def classify_hydra(code: int | None, output: str, *, timed_out: bool) -> str:
    if re.search(r"\[\d+\]\[ssh\].*login:.*password:", output):
        return "unexpected_success"
    if timed_out:
        return "timeout"
    if re.search(r"could not connect|connection refused|connection reset|no route", output, re.I):
        return "connection_error"
    if code not in (0, None) or "[ERROR]" in output:
        return "tool_error"
    if re.search(r"0 valid passwords? found", output):
        return "exhausted_without_success"
    return "unconfirmed"


def terminate_owned_process(process: subprocess.Popen[Any], grace_seconds: float = 2.0) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=grace_seconds)


def probe_once(target: str) -> dict[str, Any]:
    started = utc_now()
    before = time.monotonic()
    state = "connected"
    try:
        with socket.create_connection((target, PORT), timeout=PROBE_TIMEOUT_SECONDS):
            pass
    except TimeoutError:
        state = "timeout"
    except ConnectionRefusedError:
        state = "refused"
    except OSError:
        # 원문 예외에는 주소가 포함될 수 있으므로 공유 가능한 상태만 보존한다.
        state = "network_error"
    return {
        "started_at": started,
        "ended_at": utc_now(),
        "elapsed_ms": round((time.monotonic() - before) * 1000, 3),
        "state": state,
    }


def wait_capture_ready(process: subprocess.Popen[Any], stderr_path: Path) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        text = stderr_path.read_text(encoding="utf-8", errors="replace")
        if "listening on" in text:
            return
        if process.poll() is not None:
            break
        time.sleep(0.05)
    raise MeasurementError("패킷 캡처 준비를 확인하지 못해 공격을 시작하지 않았습니다.", 22)


def require_capture_alive(
    capture: subprocess.Popen[Any], hydra_process: subprocess.Popen[Any]
) -> None:
    """증거 캡처가 먼저 끝나면 공격을 즉시 중단해 불완전한 실측을 차단한다."""
    if capture.poll() is None:
        return
    if hydra_process.poll() is None:
        terminate_owned_process(hydra_process)
    raise MeasurementError("패킷 캡처가 실측 도중 조기 종료되어 Hydra와 탐침을 중단했습니다.", 22)


def observe_attack_window(
    target: str,
    hydra_process: subprocess.Popen[Any],
    capture: subprocess.Popen[Any],
    hydra_log: Path,
    *,
    observer: Callable[[str, dict[str, Any]], None] | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """캡처 생존을 감시하며 탐침 스케줄과 독립적인 Hydra deadline을 집행한다."""
    hydra_started = time.monotonic()
    hydra_deadline = hydra_started + HYDRA_SECONDS
    probes: list[dict[str, Any]] = []
    hydra_timed_out = False

    for index in range(PROBE_COUNT):
        scheduled = hydra_started + index * PROBE_INTERVAL_SECONDS
        while time.monotonic() < scheduled:
            require_capture_alive(capture, hydra_process)
            raw = hydra_log.read_text(encoding="utf-8", errors="replace")
            if classify_hydra(hydra_process.poll(), raw, timed_out=False) == ("unexpected_success"):
                terminate_owned_process(hydra_process)
                return probes, hydra_timed_out
            if hydra_process.poll() is None and time.monotonic() >= hydra_deadline:
                terminate_owned_process(hydra_process)
                hydra_timed_out = True
            remaining = scheduled - time.monotonic()
            time.sleep(min(0.05, max(0, remaining)))

        require_capture_alive(capture, hydra_process)
        if observer is not None:
            observer("countdown", {"remaining_seconds": max(0, hydra_deadline - time.monotonic())})
        probes.append(probe_once(target) | {"index": index + 1})
        if observer is not None:
            observer("probe", probes[-1])
        require_capture_alive(capture, hydra_process)
        raw = hydra_log.read_text(encoding="utf-8", errors="replace")
        if classify_hydra(hydra_process.poll(), raw, timed_out=False) == ("unexpected_success"):
            terminate_owned_process(hydra_process)
            return probes, hydra_timed_out
        if hydra_process.poll() is None and time.monotonic() >= hydra_deadline:
            terminate_owned_process(hydra_process)
            hydra_timed_out = True

    while hydra_process.poll() is None:
        require_capture_alive(capture, hydra_process)
        raw = hydra_log.read_text(encoding="utf-8", errors="replace")
        if classify_hydra(hydra_process.poll(), raw, timed_out=False) == ("unexpected_success"):
            terminate_owned_process(hydra_process)
            return probes, hydra_timed_out
        remaining = hydra_deadline - time.monotonic()
        if remaining <= 0:
            terminate_owned_process(hydra_process)
            return probes, True
        time.sleep(min(0.05, remaining))

    return probes, hydra_timed_out


def write_candidates(path: Path) -> None:
    values = [f"WRONG-P3-3-{secrets.token_hex(16)}" for _ in range(CANDIDATE_COUNT)]
    path.write_text("\n".join(values) + "\n", encoding="utf-8")
    path.chmod(0o600)


def sha256_file(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"sha256": digest.hexdigest(), "bytes": path.stat().st_size}


def analyze_pcap(tshark: str, pcap: Path, output: Path) -> int:
    command = [
        tshark,
        "-r",
        str(pcap),
        "-n",
        "-o",
        "tcp.relative_sequence_numbers:TRUE",
        "-Y",
        f"tcp.port == {PORT}",
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "tcp.stream",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.flags",
        "-e",
        "tcp.seq",
        "-e",
        "tcp.ack",
        "-e",
        "tcp.analysis.retransmission",
    ]
    with output.open("x", encoding="utf-8") as stream:
        result = subprocess.run(
            command, stdout=stream, stderr=subprocess.PIPE, text=True, check=False
        )
    if result.returncode != 0:
        raise MeasurementError("TShark 원본 PCAP 분석에 실패했습니다.", 22)
    return max(0, len(output.read_text(encoding="utf-8").splitlines()) - 1)


def run_measurement(
    config: Config,
    *,
    observer: Callable[[str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    bash = require_tool("bash")
    hydra = require_tool("hydra")
    tcpdump = require_tool("tcpdump")
    tshark = require_tool("tshark")
    hydra_version = check_hydra(hydra)
    capture_script = Path(__file__).with_name("tcpdump_capture.sh").resolve(strict=True)
    create_execution_guard(config.evidence_root)

    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
    run_dir = config.evidence_root / run_id
    run_dir.mkdir(mode=0o700)
    if observer is not None:
        observer("evidence", {"directory": str(run_dir)})
    pcap = run_dir / "capture.pcap"
    capture_stderr = run_dir / "capture.stderr"
    hydra_log = run_dir / "hydra.private.log"
    tshark_csv = run_dir / "tshark-tcp.private.csv"
    capture: subprocess.Popen[Any] | None = None
    hydra_process: subprocess.Popen[Any] | None = None
    started_at = utc_now()
    interrupted = False
    hydra_timed_out = False

    try:
        with capture_stderr.open("x", encoding="utf-8") as capture_errors:
            capture = subprocess.Popen(
                [
                    bash,
                    str(capture_script),
                    config.target,
                    str(PORT),
                    config.interface,
                    str(pcap),
                    str(CAPTURE_SECONDS),
                    str(CAPTURE_PACKETS),
                ],
                stdout=subprocess.DEVNULL,
                stderr=capture_errors,
                start_new_session=True,
            )
            capture_started = time.monotonic()
            wait_capture_ready(capture, capture_stderr)
            baseline = probe_once(config.target)
            if observer is not None:
                observer("baseline", baseline)
            if baseline["state"] != "connected":
                raise MeasurementError(
                    "공격 전 TCP 기준선이 실패해 Hydra를 시작하지 않았습니다.", 20
                )

            with tempfile.TemporaryDirectory(prefix="private-", dir=run_dir) as private:
                candidates = Path(private) / "candidates"
                write_candidates(candidates)
                with hydra_log.open("x", encoding="utf-8") as hydra_output:
                    # 호출 직전·종료 확인 시각은 PCAP 첫 SYN 및 서버 로그와 대조할 경계값이다.
                    # 프로세스 생성 시각을 최초 인증 실패 시각으로 간주하지 않는다.
                    hydra_started_at = utc_now()
                    hydra_process = subprocess.Popen(
                        build_hydra_command(hydra, config, candidates),
                        cwd=private,
                        stdout=hydra_output,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )
                    if observer is not None:
                        observer("attack_started", {"started_at": hydra_started_at})
                    probes, hydra_timed_out = observe_attack_window(
                        config.target, hydra_process, capture, hydra_log, observer=observer
                    )
                    hydra_code = hydra_process.wait()
                    hydra_exit_observed_at = utc_now()

            try:
                remaining = CAPTURE_SECONDS + 5 - (time.monotonic() - capture_started)
                capture_code = capture.wait(timeout=max(1, remaining))
            except subprocess.TimeoutExpired:
                terminate_owned_process(capture)
                capture_code = capture.returncode
    except KeyboardInterrupt:
        interrupted = True
        if hydra_process is not None:
            terminate_owned_process(hydra_process)
        if capture is not None:
            terminate_owned_process(capture)
        raise MeasurementError("사용자 중단으로 소유 프로세스를 종료했습니다.", 130) from None
    except BaseException:
        if hydra_process is not None:
            terminate_owned_process(hydra_process)
        if capture is not None:
            terminate_owned_process(capture)
        raise

    raw_hydra = hydra_log.read_text(encoding="utf-8", errors="replace")
    hydra_state = classify_hydra(hydra_code, raw_hydra, timed_out=hydra_timed_out)
    if capture_code != 124 or not pcap.is_file():
        raise MeasurementError(
            "패킷 캡처가 시간 상한 전에 종료되었거나 유효한 증거를 만들지 못했습니다.", 22
        )
    packet_rows = analyze_pcap(tshark, pcap, tshark_csv)
    evidence = {
        path.name: sha256_file(path)
        for path in (pcap, capture_stderr, hydra_log, tshark_csv)
        if path.is_file()
    }
    source_ip = config.evidence_root / "source-public-ip.private"
    if source_ip.is_file():
        evidence[source_ip.name] = sha256_file(source_ip)
    manifest = {
        "schema": "cloudshield-p3-3-private-evidence-v1",
        "run_id": run_id,
        "started_at": started_at,
        "ended_at": utc_now(),
        "target": TARGET_LABEL,
        "port": PORT,
        "interface": config.interface,
        "limits": plan(),
        "baseline": baseline,
        "probes": probes,
        "hydra": {
            "started_at": hydra_started_at,
            "exit_observed_at": hydra_exit_observed_at,
            "state": hydra_state,
            "exit_code": hydra_code,
            "candidate_count": CANDIDATE_COUNT,
            "concurrency": 1,
            "version": hydra_version,
        },
        "capture": {
            "exit_code": capture_code,
            "packet_rows": packet_rows,
            "tcpdump_version": tool_version(tcpdump, "--version"),
            "tshark_version": tool_version(tshark, "--version"),
        },
        "interrupted": interrupted,
        "pipeline_verdict": "not_evaluated_without_server_aws_slack_evidence",
        "evidence": evidence,
    }
    manifest_path = run_dir / "manifest.private.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    manifest_path.chmod(0o600)
    summary = {
        "run_id": run_id,
        "target": TARGET_LABEL,
        "hydra_state": hydra_state,
        "hydra_started_at": hydra_started_at,
        "capture_packet_rows": packet_rows,
        "manifest_sha256": sha256_file(manifest_path)["sha256"],
        "pipeline_verdict": manifest["pipeline_verdict"],
    }
    if hydra_state == "unexpected_success":
        raise MeasurementError("예상치 못한 인증 성공을 탐지해 즉시 중단했습니다.", 10)
    if hydra_state != "exhausted_without_success":
        raise MeasurementError("Hydra 결과를 인증 실패 재현으로 확정할 수 없습니다.", 21)
    return summary


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="P3-3 단일 EC2 Hydra/L4 계측")
    result.add_argument("command", nargs="?", choices=("plan", "run"), default="plan")
    result.add_argument("--execute", action="store_true")
    result.add_argument("--interface", default="eth0")
    result.add_argument("--evidence-root", default="/var/lib/cloudshield-evidence/p3-3")
    return result


def main(argv: list[str] | None = None, environ: dict[str, str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "plan":
        if args.execute:
            print("plan에서는 --execute를 사용할 수 없습니다.", file=sys.stderr)
            return 2
        print(json.dumps(plan(), ensure_ascii=False))
        return 0
    if not args.execute:
        print("실측 실행에는 run --execute가 모두 필요합니다.", file=sys.stderr)
        return 2
    try:
        config = load_config(args, dict(os.environ if environ is None else environ))
        print(json.dumps(run_measurement(config), ensure_ascii=False))
        return 0
    except PreparationError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except MeasurementError as exc:
        print(str(exc), file=sys.stderr)
        return exc.code
    except (OSError, subprocess.SubprocessError):
        # 주소·계정·외부 도구 원문이 예외에 포함될 수 있어 공유 출력에는 유형만 남긴다.
        print("실측 도구 오류가 발생했습니다. 비공개 증거 디렉터리를 확인하세요.", file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
