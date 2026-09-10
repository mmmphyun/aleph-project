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


CAPTURE_SCRIPT = SCRIPT.with_name("tcpdump_capture.sh")


@pytest.fixture
def capture(tmp_path, bash):
    """PATH를 화이트리스트로 구성하여 실제 tcpdump 폴백을 구조적으로 막는다."""
    fake_bin = tmp_path / "fake bin"
    fake_bin.mkdir()
    fake = fake_bin / "tcpdump"
    fake.write_text(
        r"""#!/bin/bash
printf '%s\n' "$@" > "$ARGS"
printf '%s\n' "$$" > "$PID_FILE"
printf 'MOCK ONLY - NOT PCAP\n'
if [[ $MODE == exit ]]; then exit "$CAPTURE_STATUS"; fi
trap 'printf "flushed\n" >> "$EVENTS"; printf "MOCK FLUSH\n"; exit 0' TERM
if [[ $MODE == stubborn ]]; then trap '' TERM; fi
if [[ $MODE == INT || $MODE == TERM ]]; then kill -s "$MODE" "$PPID"; fi
# 테스트 자체가 실패해도 모의 프로세스는 6초 내 자율 종료한다.
SECONDS=0
while (( SECONDS < 6 )); do /bin/sleep 0.05; done
exit 99
""",
        encoding="utf-8",
        newline="\n",
    )
    fake.chmod(0o755)
    sleeper = fake_bin / "sleep"
    sleeper.write_text('#!/bin/bash\nexec /bin/sleep "$@"\n', newline="\n")
    sleeper.chmod(0o755)
    args_file = tmp_path / "args"
    pid_file = tmp_path / "pid"
    events = tmp_path / "events"
    output = tmp_path / "capture with spaces.pcap"

    def run(arguments=None, *, mode="exit", status=0, missing=None):
        if missing:
            (fake_bin / missing).unlink()
        env = os.environ.copy()
        for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            env.pop(name, None)
        env.update(
            FAKE_BIN=fake_bin.as_posix(),
            ARGS=args_file.as_posix(),
            PID_FILE=pid_file.as_posix(),
            EVENTS=events.as_posix(),
            MODE=mode,
            CAPTURE_STATUS=str(status),
            MSYS_NO_PATHCONV="1",
        )
        if arguments is None:
            arguments = ["192.0.2.10", "22", "eth0", output.as_posix()]
        # 스크립트 계약은 POSIX 경로이며 Windows 테스트 경로만 MSYS 표기로 변환한다.
        arguments = [
            f"/{arg[0].lower()}{arg[2:]}" if len(arg) > 2 and arg[1:3] == ":/" else arg
            for arg in arguments
        ]
        result = subprocess.run(
            [
                bash,
                "--noprofile",
                "--norc",
                "-c",
                'cd "$FAKE_BIN" || exit; export PATH="$PWD"; '
                'exec /bin/bash --noprofile --norc "$@"',
                "test-capture",
                CAPTURE_SCRIPT.as_posix(),
                *arguments,
            ],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=12,
            check=False,
        )
        if pid_file.exists():
            # Bash PID 검사는 Git Bash/MSYS와 Linux 양쪽에서 같은 의미를 갖는다.
            alive = subprocess.run(
                [bash, "-c", 'kill -0 "$1" 2>/dev/null', "check", pid_file.read_text().strip()],
                capture_output=True,
                timeout=3,
                check=False,
            )
            assert alive.returncode != 0, "시작한 모의 tcpdump가 남아 있습니다."
        return result

    return run, output, args_file, events


def test_capture_exact_arguments_and_safe_output(capture):
    run, output, args_file, _ = capture
    result = run()
    assert result.returncode == 0, result.stderr
    assert args_file.read_text().splitlines() == [
        "-nn",
        "-p",
        "-U",
        "-i",
        "eth0",
        "-c",
        "1000",
        "-w",
        "-",
        "ip",
        "and",
        "tcp",
        "and",
        "host",
        "192.0.2.10",
        "and",
        "port",
        "22",
    ]
    assert output.read_text() == "MOCK ONLY - NOT PCAP\n"


@pytest.mark.parametrize("status", [1, 42, 124, 126, 127, 130, 143, 255])
def test_capture_preserves_failure_codes(capture, status):
    run, _, _, _ = capture
    result = run(status=status)
    assert result.returncode == status
    assert "tcpdump 실행 실패" in result.stderr


@pytest.mark.parametrize(
    "index,value",
    [
        *[(0, v) for v in ["", "example.org", "::1", "256.1.1.1", "01.2.3.4", "1.2.3.4;id"]],
        *[(1, v) for v in ["0", "65536", "022", "-1", "9" * 50]],
        *[(2, v) for v in ["", "any", "-i", "eth 0", "eth0;id", "a" * 16]],
        *[(3, v) for v in ["", "out.txt", "missing/out.pcap", "bad\n.pcap"]],
        *[(4, v) for v in ["0", "121", "01", "x", "9" * 50]],
        *[(5, v) for v in ["0", "100001", "01", "x", "9" * 50]],
    ],
)
def test_capture_rejects_invalid_input_before_execution(capture, index, value):
    run, output, args_file, _ = capture
    arguments = ["192.0.2.10", "22", "eth0", output.as_posix(), "10", "1000"]
    arguments[index] = value
    result = run(arguments)
    assert result.returncode == 2, result.stderr
    assert not args_file.exists()
    assert not output.exists()


@pytest.mark.parametrize("arguments", [[], ["192.0.2.1"], ["x"] * 7])
def test_capture_argument_count(capture, arguments):
    run, _, args_file, _ = capture
    assert run(arguments).returncode == 2
    assert not args_file.exists()


def test_capture_existing_file_is_preserved(capture):
    run, output, args_file, _ = capture
    output.write_text("existing evidence")
    assert run().returncode == 2
    assert output.read_text() == "existing evidence"
    assert not args_file.exists()


@pytest.mark.parametrize("missing", ["tcpdump", "sleep"])
def test_capture_missing_command_never_falls_back(capture, missing):
    run, output, args_file, _ = capture
    result = run(missing=missing)
    assert result.returncode == 127
    assert missing in result.stderr
    assert not output.exists()
    assert not args_file.exists()


@pytest.mark.parametrize(
    "mode,code", [("hang", 124), ("INT", 130), ("TERM", 143), ("stubborn", 124)]
)
def test_capture_timeout_and_signal_cleanup(capture, mode, code):
    run, output, _, events = capture
    result = run(["192.0.2.10", "22", "eth0", output.as_posix(), "1", "1"], mode=mode)
    assert result.returncode == code, result.stderr
    if mode == "stubborn":
        assert "SIGKILL" in result.stderr
        assert not events.exists()
    else:
        assert events.read_text() == "flushed\n"
        assert "MOCK FLUSH" in output.read_text()


def test_capture_limit_boundaries_and_syntax(capture, bash):
    run, output, args_file, _ = capture
    result = run(["255.0.0.1", "65535", "eth0.1", output.as_posix(), "120", "100000"])
    assert result.returncode == 0, result.stderr
    assert "100000" in args_file.read_text().splitlines()
    syntax = subprocess.run(
        [bash, "-n", CAPTURE_SCRIPT.as_posix()], capture_output=True, check=False
    )
    assert syntax.returncode == 0, syntax.stderr


def test_capture_relative_path_and_shell_metacharacters(capture):
    run, _, args_file, _ = capture
    name = "capture $(touch INJECTED); literal.pcap"
    result = run(["192.0.2.1", "1", "lo", name, "1", "1"])
    assert result.returncode == 0, result.stderr
    fake_bin = args_file.parent / "fake bin"
    assert (fake_bin / name).read_text() == "MOCK ONLY - NOT PCAP\n"
    assert not (fake_bin / "INJECTED").exists()


def test_capture_output_directory_is_rejected(capture):
    run, output, args_file, _ = capture
    output.mkdir()
    assert run().returncode == 2
    assert output.is_dir()
    assert not args_file.exists()


def test_capture_unrelated_process_survives(capture, bash):
    run, output, args_file, _ = capture
    # 별도 모의 tcpdump도 같은 이름으로 실행하여 광역 프로세스 종료 회귀를 검출한다.
    fake = args_file.parent / "fake bin" / "tcpdump"
    env = os.environ.copy()
    env.update(
        MODE="hang",
        ARGS=(args_file.parent / "other-args").as_posix(),
        PID_FILE=(args_file.parent / "other-pid").as_posix(),
        EVENTS=(args_file.parent / "other-events").as_posix(),
    )
    other = subprocess.Popen(
        [bash, "--noprofile", "--norc", "-c", 'exec "$1"', "other", fake.as_posix()],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        assert (
            run(["192.0.2.1", "22", "eth0", output.as_posix(), "1"], mode="hang").returncode == 124
        )
        assert other.poll() is None
    finally:
        other_pid = args_file.parent / "other-pid"
        if other_pid.exists():
            subprocess.run(
                [bash, "-c", 'kill -TERM "$1"', "cleanup", other_pid.read_text().strip()],
                capture_output=True,
                timeout=3,
                check=False,
            )
        other.wait(timeout=8)
