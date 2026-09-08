"""실제 네트워크 요청 없이 입력 제한과 Hydra 실행 계약을 검증한다."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash") or "C:/Program Files/Git/bin/bash.exe"
pytestmark = pytest.mark.skipif(not Path(BASH).is_file(), reason="Bash 필요")


def run_script(arguments, words="invalid-test-password\n", mock_status=0):
    # 임시 실행 파일로 외부 도구를 대체하여 AWS/SSH 연결 없이 실패 전파를 확인한다.
    script = r"""
set -euo pipefail
testdir=$(mktemp -d)
trap 'rm -rf -- "$testdir"' EXIT
printf '%s' "$WORDS" > "$testdir/words.txt"
printf '#!/usr/bin/env bash\nprintf "MOCK_HYDRA"\nprintf " <%%s>" "$@"\nexit %s\n' \
    "$MOCK_STATUS" > "$testdir/hydra"
chmod +x "$testdir/hydra"
export PATH="$testdir:$PATH"
bash network/attack_simulation.sh "$1" "$2" "$testdir/words.txt" admin "${3:-}"
"""
    return subprocess.run(
        [BASH, "-c", script, "test", *arguments],
        cwd=ROOT,
        env={**os.environ, "WORDS": words, "MOCK_STATUS": str(mock_status)},
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=15,
    )


def test_preview_does_not_launch_hydra():
    result = run_script(["192.0.2.10", "22"])
    assert result.returncode == 0, result.stderr
    assert "MOCK_HYDRA" not in result.stdout


@pytest.mark.parametrize(
    "target,port",
    [
        ("999.1.1.1", "22"),
        ("01.2.3.4", "22"),
        ("-x", "22"),
        ("192.0.2.10", "0"),
        ("192.0.2.10", "65536"),
        ("192.0.2.10", "abc"),
    ],
)
def test_invalid_endpoint(target, port):
    result = run_script([target, port, "--execute"])
    assert result.returncode != 0
    assert "MOCK_HYDRA" not in result.stdout


@pytest.mark.parametrize("words", ["", "\n", "x\n" * 101, "x" * 129])
def test_wordlist_limits(words):
    result = run_script(["192.0.2.10", "22", "--execute"], words=words)
    assert result.returncode != 0
    assert "MOCK_HYDRA" not in result.stdout


@pytest.mark.parametrize("status", [0, 7, 124])
def test_execution_arguments_and_exit_status(status):
    result = run_script(["192.0.2.10", "2222", "--execute"], mock_status=status)
    assert result.returncode == status, result.stderr
    assert "<-s> <2222> <-t> <4> <-f> <192.0.2.10> <ssh>" in result.stdout
