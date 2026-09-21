"""전용 컨테이너 내부 실행기. stdin의 러너 검증 결과만 사용하며 원문 출력은 보존하지 않는다."""

import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path


def validate(spec):
    ipaddress.IPv4Address(spec["target"])
    if spec["port"] != 2222 or spec["tasks"] != 1:
        raise ValueError("포트 2222 / 동시성 1만 허용")
    if not 1 <= spec["candidates"] <= 10 or not 3 <= spec["seconds"] <= 55:
        raise ValueError("후보 1~10 / 시간 3~55초만 허용")
    if not re.fullmatch(r"cs-ssh-[0-9a-f]{32}", spec["run_id"]):
        raise ValueError("실행 소유권 식별자 오류")


def classify(code, output, timed_out=False, interrupted=False):
    # 종료 코드 0은 인증 실패 재현의 증거가 아니다. 서버 로그는 호스트가 별도 확인한다.
    if re.search(r"\[\d+\]\[ssh\].*login:.*password:", output):
        return "unexpected_success"
    if interrupted:
        return "interrupted"
    if timed_out:
        return "timeout"
    if re.search(r"could not connect|connection refused|Connection reset|no route", output, re.I):
        return "connection_error"
    if code or "[ERROR]" in output:
        return "tool_error"
    if re.search(r"0 valid passwords? found", output):
        return "exhausted_without_success"
    return "unconfirmed"


def command(binary, spec, candidates):
    validate(spec)
    return [
        binary,
        "-I",
        "-K",
        "-f",
        "-l",
        "hydralab",
        "-P",
        str(candidates),
        "-t",
        "1",
        "-w",
        "3",
        "-s",
        "2222",
        spec["target"],
        "ssh",
    ]


def execute(spec):
    validate(spec)
    binary = shutil.which("hydra")
    if not binary:
        raise RuntimeError("Hydra 미설치")
    help_result = subprocess.run([binary, "-h"], capture_output=True, text=True, timeout=5)
    help_text = help_result.stdout + help_result.stderr
    services = re.search(r"Supported services:\s*([^\r\n]+)", help_text)
    if not services or "ssh" not in services[1].split() or "-K" not in help_text:
        raise RuntimeError("Hydra SSH 모듈 없음")
    os.umask(0o077)
    # tmpfs 안의 0700 디렉터리에서만 후보·Hydra 출력·복구 파일을 생성한다.
    # 이 함수가 실패해도 TemporaryDirectory가 제거하며 SIGKILL은 컨테이너 정리로 보완한다.
    started = datetime.now(UTC).isoformat()
    timed_out = interrupted = False
    with tempfile.TemporaryDirectory(prefix="hydra-", dir="/run/private") as directory:
        folder = Path(directory)
        candidates = folder / "candidates"
        candidates.write_text(
            "".join("WRONG-" + secrets.token_hex(16) + "\n" for _ in range(spec["candidates"]))
        )
        with (folder / "output").open("w+") as output:
            deadline = time.monotonic() + spec["seconds"]
            proc = subprocess.Popen(
                command(binary, spec, candidates),
                cwd=folder,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                while proc.poll() is None:
                    if classify(0, (folder / "output").read_text()) in (
                        "unexpected_success",
                        "connection_error",
                        "tool_error",
                    ):
                        break
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    time.sleep(0.05)
            except KeyboardInterrupt:
                interrupted = True
            finally:
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=1)
            state = classify(
                proc.returncode, (folder / "output").read_text(), timed_out, interrupted
            )
        result = {
            "state": state,
            "exit": proc.returncode,
            "start_utc": started,
            "end_utc": datetime.now(UTC).isoformat(),
            "candidates": spec["candidates"],
            "tasks": 1,
            "seconds": spec["seconds"],
            "hydra_version": help_text.splitlines()[0] if help_text else "unknown",
        }
    return result


def main():
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        result = execute(json.load(sys.stdin))
    except KeyboardInterrupt:
        result = {"state": "interrupted"}
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
        # 예외 원문/입력은 자격증명이 섞일 수 있어 출력하지 않는다.
        result = {"state": "tool_error"}
    print(json.dumps(result))
    return 0 if result["state"] == "exhausted_without_success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
