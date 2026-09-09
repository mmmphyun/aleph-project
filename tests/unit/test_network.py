"""실제 SSH 대신 격리된 PATH의 가짜 실행 파일로 네트워크 부작용 없이 검증한다."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "network" / "ssh_single_connect.sh"


@pytest.fixture(scope="module")
def bash():
    candidates = [
        Path("C:/Program Files/Git/bin/bash.exe"),
        Path(shutil.which("bash") or "/bin/bash"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    pytest.fail("로컬 Bash가 필요합니다. Git Bash 또는 Bash를 설치하세요.")


@pytest.fixture
def run_ssh(tmp_path, bash):
    # PATH에는 가짜 SSH만 두어 테스트 오류 시에도 실제 ssh로 폴백하지 않는다.
    fake_bin = tmp_path / "fake bin"
    fake_bin.mkdir()
    (fake_bin / "ssh").write_text(
        '#!/bin/bash\nprintf "call\\n" >> "$CALLS"\n'
        'printf "%s\\n" "$@" > "$ARGS"\nexit "$SSH_STATUS"\n',
        encoding="utf-8",
        newline="\n",
    )
    (fake_bin / "ssh").chmod(0o755)
    calls = tmp_path / "calls"
    args_file = tmp_path / "args"

    def run(arguments, status=0):
        env = os.environ.copy()
        for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            env.pop(name, None)
        env.update(
            FAKE_BIN=fake_bin.as_posix(),
            CALLS=calls.as_posix(),
            ARGS=args_file.as_posix(),
            SSH_STATUS=str(status),
            MSYS_NO_PATHCONV="1",
        )
        result = subprocess.run(
            [
                bash,
                "--noprofile",
                "--norc",
                "-c",
                'cd "$FAKE_BIN" || exit; export PATH="$PWD"; '
                'script=$1; shift; source "$script" "$@"',
                "test-network",
                SCRIPT.as_posix(),
                *arguments,
            ],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
            check=False,
        )
        return (
            result,
            calls.read_text().splitlines() if calls.exists() else [],
            args_file.read_text().splitlines() if args_file.exists() else [],
        )

    return run


@pytest.mark.parametrize("status", [0, 1, 42, 255])
def test_single_connection_and_exit_status(run_ssh, status):
    result, calls, args = run_ssh(["192.0.2.10", "tester"], status)
    assert result.returncode == status, result.stderr
    assert calls == ["call"]
    assert args == [
        "-F",
        "/dev/null",
        "-T",
        "-n",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "NumberOfPasswordPrompts=0",
        "-o",
        "ClearAllForwardings=yes",
        "-p",
        "22",
        "-l",
        "tester",
        "192.0.2.10",
        "true",
    ]


@pytest.mark.parametrize("port, timeout", [("1", "1"), ("2222", "10"), ("65535", "120")])
def test_custom_limits(run_ssh, port, timeout):
    result, calls, args = run_ssh(["255.0.0.1", "_test-user", port, timeout])
    assert result.returncode == 0, result.stderr
    assert calls == ["call"]
    assert args[args.index("-p") + 1] == port
    assert f"ConnectTimeout={timeout}" in args


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["192.0.2.1"],
        ["192.0.2.1", "u", "22", "5", "extra"],
        *[
            [host, "u"]
            for host in [
                "",
                "example.com",
                "::1",
                "256.0.0.1",
                "192.0.2",
                "01.2.3.4",
                "-oProxyCommand=x",
                "1.2.3.4;id",
            ]
        ],
        *[["192.0.2.1", user] for user in ["", "-root", "a b", "a;id", "a" * 33]],
        *[["192.0.2.1", "u", port] for port in ["", "0", "65536", "022", "-1", "x", "9" * 50]],
        *[["192.0.2.1", "u", "22", limit] for limit in ["", "0", "121", "01", "-1", "x"]],
    ],
)
def test_invalid_input_never_calls_ssh(run_ssh, arguments):
    result, calls, args = run_ssh(arguments)
    assert result.returncode == 2
    assert result.stderr
    assert calls == []
    assert args == []


def test_bash_syntax(bash):
    result = subprocess.run([bash, "-n", SCRIPT.as_posix()], capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
