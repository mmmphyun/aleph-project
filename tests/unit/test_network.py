"""실제 SSH 대신 격리된 PATH의 가짜 실행 파일로 네트워크 부작용 없이 검증한다."""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def hydra_lab(tmp_path, monkeypatch):
    directory = Path(__file__).resolve().parents[2] / "network/lab"
    monkeypatch.syspath_prepend(str(directory))
    modules = []
    for name in ("hydra_lab", "hydra_worker"):
        spec = importlib.util.spec_from_file_location(name, directory / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
    host, worker = modules
    return host, worker, host.HydraLab(tmp_path / "hydra")


@pytest.mark.parametrize("args", [[], ["run"], ["plan", "--execute"]])
def test_hydra_default_is_dry_run(hydra_lab, monkeypatch, args):
    host, _, _ = hydra_lab
    monkeypatch.setattr(host.HydraLab, "preflight", lambda *_: pytest.fail("Docker called"))
    assert host.main(args) == 0


@pytest.mark.parametrize(
    "option,value",
    [
        ("--candidates", "0"),
        ("--candidates", "11"),
        ("--seconds", "56"),
        ("--seconds", "0"),
        ("--tasks", "2"),
        ("--port", "22"),
        ("--target", "10.0.0.1"),
    ],
)
def test_hydra_invalid_limits_before_docker(hydra_lab, option, value):
    host, _, _ = hydra_lab
    with pytest.raises(SystemExit) as exc:
        host.main(["run", "--execute", option, value])
    assert exc.value.code == 2


def hydra_spec():
    return dict(
        target="192.0.2.2", port=2222, tasks=1, candidates=6, seconds=3, run_id="cs-ssh-" + "a" * 32
    )


def test_hydra_command_is_bounded_argv(hydra_lab):
    _, worker, _ = hydra_lab
    path = Path("literal ; $(touch BAD)")
    argv = worker.command("hydra", hydra_spec(), path)
    assert argv[argv.index("-P") + 1] == str(path)
    assert argv[argv.index("-t") + 1] == "1"
    assert argv[-2:] == ["192.0.2.2", "ssh"]
    assert {"-f", "-K", "-I"} <= set(argv)
    assert not {"-p", "-V", "-R", "-e"} & set(argv)
    with pytest.raises(ValueError):
        worker.command("hydra", dict(hydra_spec(), target="127.0.0.1;id"), path)


@pytest.mark.parametrize("role", ["server", "client"])
def test_hydra_create_is_private_and_exactly_owned(hydra_lab, monkeypatch, role):
    _, _, lab = hydra_lab
    lab.network, lab.image_id = "owned-network", "sha256:owned-image"
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "owned-id", "")

    monkeypatch.setattr(lab, "call", fake)
    assert lab.create(role) == "owned-id"
    args = calls[0]
    assert args[args.index("--network") + 1] == "owned-network"
    assert args[args.index("--tmpfs") + 1] == "/run/private:rw,noexec,nosuid,mode=0700"
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert not {"--privileged", "-p", "--publish", "--mount", "-v", "--volume"} & set(args)
    assert "sha256:owned-image" in args
    assert lab.containers == ["owned-id"]


def test_hydra_failed_create_never_claims_foreign_resource(hydra_lab, monkeypatch):
    _, _, lab = hydra_lab

    def fail(*a, **k):
        raise RuntimeError("name already exists")

    monkeypatch.setattr(lab, "call", fail)
    with pytest.raises(RuntimeError):
        lab.create("server")
    assert lab.containers == []


def test_hydra_server_logs_independently_count_failures_and_success(hydra_lab, monkeypatch):
    _, _, lab = hydra_lab
    log = (
        "Failed password for hydralab from 192.0.2.3 port 4000 ssh2\n" * 3
        + "Failed password for hydralab from 192.0.2.4 port 4001 ssh2\n"
        + "Accepted password for hydralab from 192.0.2.3 port 4000 ssh2\n"
    )
    monkeypatch.setattr(lab, "call", lambda *a, **k: subprocess.CompletedProcess(a, 0, "", log))
    assert lab.server_evidence("server", "192.0.2.3") == (3, 1)
    assert (lab.output / "sshd.log").read_text() == log


@pytest.mark.parametrize(
    "code,text,timed,interrupted,state",
    [
        (0, "", False, False, "unconfirmed"),
        (0, "0 valid passwords found", False, False, "exhausted_without_success"),
        (
            0,
            "[2222][ssh] host: X login: hydralab password: secret",
            False,
            False,
            "unexpected_success",
        ),
        (1, "[ERROR] could not connect", False, False, "connection_error"),
        (1, "[ERROR] bad module", False, False, "tool_error"),
        (-15, "", True, False, "timeout"),
        (-15, "", False, True, "interrupted"),
    ],
)
def test_hydra_result_classification(hydra_lab, code, text, timed, interrupted, state):
    assert hydra_lab[1].classify(code, text, timed, interrupted) == state


@pytest.mark.parametrize("help_text", [None, "Supported services: ftp\nssh not compiled", ""])
def test_hydra_missing_tool_or_ssh_never_executes(hydra_lab, monkeypatch, help_text):
    _, worker, _ = hydra_lab
    monkeypatch.setattr(
        worker.shutil, "which", lambda _: "hydra" if help_text is not None else None
    )
    monkeypatch.setattr(
        worker.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 255, help_text, "")
    )
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *a, **k: pytest.fail("Hydra invoked"))
    with pytest.raises(RuntimeError):
        worker.execute(hydra_spec())


@pytest.mark.parametrize("mode", ["normal", "timeout", "interrupt", "success", "launch_error"])
def test_hydra_worker_removes_secrets_and_owned_process_group(
    hydra_lab, monkeypatch, tmp_path, mode
):
    _, worker, _ = hydra_lab
    original_temp = tempfile.TemporaryDirectory
    monkeypatch.setattr(
        worker.tempfile,
        "TemporaryDirectory",
        lambda **kw: original_temp(prefix="private-", dir=tmp_path),
    )
    monkeypatch.setattr(worker.os, "umask", lambda _: None)
    monkeypatch.setattr(worker.shutil, "which", lambda _: "fake-hydra")
    monkeypatch.setattr(
        worker.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a, 255, "Hydra MOCK\n-K\nSupported services: ssh\n", ""
        ),
    )
    clock = iter([0, 4])
    monkeypatch.setattr(worker.time, "monotonic", lambda: next(clock))
    killed = []
    monkeypatch.setattr(worker.os, "killpg", lambda pid, sig: killed.append(pid), raising=False)
    created = []

    class FakeHydra:
        pid = 7123
        returncode = None

        def __init__(self, argv, cwd, stdout, **kwargs):
            created.append(cwd)
            candidates = (cwd / "candidates").read_text().splitlines()
            assert len(candidates) == 6 and all(p.startswith("WRONG-") for p in candidates)
            assert all(p not in " ".join(argv) for p in candidates)
            (cwd / "hydra.restore").write_text("MOCK PRIVATE")
            if mode == "launch_error":
                raise OSError("mock launch failure")
            stdout.write(
                "[2222][ssh] login: hydralab password: secret"
                if mode == "success"
                else "0 valid passwords found"
                if mode == "normal"
                else ""
            )
            stdout.flush()
            if mode == "normal":
                self.returncode = 0

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            self.returncode = -15
            return -15

    def interrupt():
        raise KeyboardInterrupt()

    if mode == "interrupt":
        values = iter([0])
        monkeypatch.setattr(
            worker.time, "monotonic", lambda: next(values) if not created else interrupt()
        )
    monkeypatch.setattr(worker.subprocess, "Popen", FakeHydra)
    if mode == "launch_error":
        # 시작 직후 중단도 임시 디렉터리의 finally 정리를 검증한다.
        with pytest.raises((OSError, KeyboardInterrupt)):
            worker.execute(hydra_spec())
    else:
        result = worker.execute(hydra_spec())
        assert (
            result["state"]
            == {
                "normal": "exhausted_without_success",
                "timeout": "timeout",
                "success": "unexpected_success",
                "interrupt": "interrupted",
            }[mode]
        )
        assert "secret" not in json.dumps(result)
    assert created and not created[0].exists()
    if mode in ("timeout", "success", "interrupt"):
        assert killed == [7123]


@pytest.mark.parametrize(
    "violation",
    [None, "label", "external", "extra", "published", "privileged", "mount", "foreign", "port"],
)
def test_hydra_target_must_be_current_owned_pair(hydra_lab, monkeypatch, violation):
    host, _, lab = hydra_lab
    lab.network, lab.image_id, lab.containers = "net", "image", ["server", "client"]
    net = dict(
        Id="net",
        Internal=True,
        Driver="bridge",
        Labels={host.LABEL: lab.run_id},
        Containers={"server": {}, "client": {}},
    )
    item = dict(
        Id="server",
        Config={"Labels": {host.LABEL: lab.run_id}},
        Image="image",
        State={"Running": True},
        HostConfig={},
        Mounts=[],
        NetworkSettings={"Networks": {"net": {"NetworkID": "net", "IPAddress": "192.0.2.2"}}},
    )
    if violation == "label":
        item["Config"]["Labels"] = {}
    elif violation == "external":
        net["Internal"] = False
    elif violation == "extra":
        net["Containers"]["unrelated"] = {}
    elif violation == "published":
        item["HostConfig"]["PortBindings"] = {"2222/tcp": []}
    elif violation == "privileged":
        item["HostConfig"]["Privileged"] = True
    elif violation == "mount":
        item["Mounts"] = [{"Type": "bind"}]
    elif violation == "foreign":
        item["NetworkSettings"]["Networks"]["net"]["NetworkID"] = "foreign"

    def fake(*args, **kwargs):
        if args[0] == "network":
            value = json.dumps([net])
        elif args[0] == "inspect":
            value = json.dumps([dict(item, Id=args[1])])
        else:
            value = (
                "port 2222\npermitrootlogin no\nallowusers hydralab\n"
                "passwordauthentication yes\nauthenticationmethods password"
            )
            if violation == "port":
                value = value.replace("2222", "22")
        return subprocess.CompletedProcess(args, 0, value, "")

    monkeypatch.setattr(lab, "call", fake)
    if violation:
        with pytest.raises(RuntimeError):
            lab.verify_target("server", "client")
    else:
        assert lab.verify_target("server", "client") == ["192.0.2.2", "192.0.2.2"]


@pytest.mark.parametrize(
    "ready,code,state,failures,accepted",
    [
        (True, 124, "exhausted_without_success", 6, 0),
        (True, 0, "exhausted_without_success", 6, 0),
        (False, 1, "unconfirmed", 0, 0),
        (True, 1, "exhausted_without_success", 6, 0),
        (True, 124, "timeout", 2, 0),
        (True, 124, "exhausted_without_success", 0, 0),
        (True, 124, "unexpected_success", 0, 1),
    ],
)
def test_hydra_capture_requires_ready_and_real_log_evidence(
    hydra_lab, monkeypatch, ready, code, state, failures, accepted
):
    host, _, lab = hydra_lab
    lab.context = "local"
    calls = []
    capture_waits = []

    class Capture:
        returncode = None

        def __init__(self, args, stdout, stderr, env):
            stderr.write(b"listening on eth0\n" if ready else b"permission denied\n")
            stderr.flush()

        def poll(self):
            return self.returncode if ready else code

        def wait(self, timeout):
            capture_waits.append(timeout)
            self.returncode = code
            return code

    def fake(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, json.dumps({"state": state}), "")

    monkeypatch.setattr(host.subprocess, "Popen", Capture)
    monkeypatch.setattr(lab, "verify_target", lambda *a: ["192.0.2.2", "192.0.2.3"])
    monkeypatch.setattr(lab, "server_evidence", lambda *a: (failures, accepted))
    monkeypatch.setattr(lab, "call", fake)
    if (
        ready
        and code in (0, 124)
        and state == "exhausted_without_success"
        and failures
        and not accepted
    ):
        lab.capture_hydra("server", "client", "192.0.2.2", "192.0.2.3", "eth0")
        assert capture_waits == [lab.seconds + 6]
    else:
        with pytest.raises(RuntimeError):
            lab.capture_hydra("server", "client", "192.0.2.2", "192.0.2.3", "eth0")
    assert len(calls) == int(ready)
    assert lab.events[-1]["kernel_dropped_packets"] is None


@pytest.fixture
def docker_lab(tmp_path):
    """Docker를 import 시 실행하지 않는 전용 러너를 임시 경로에서 검증한다."""
    path = Path(__file__).resolve().parents[2] / "network/lab/run.py"
    spec = importlib.util.spec_from_file_location("network_lab_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, module.Lab(tmp_path / "run")


@pytest.mark.parametrize("role", ["client", "server"])
def test_lab_container_isolation(docker_lab, monkeypatch, role):
    _, lab = docker_lab
    lab.network = "owned-network-id"
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "owned-container-id", "")

    monkeypatch.setattr(lab, "call", fake)
    assert lab.create(role) == "owned-container-id"
    create = calls[0]
    assert create[create.index("--network") + 1] == "owned-network-id"
    assert create[create.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges:true" in create
    assert not {"--privileged", "--publish", "-p", "--mount", "--volume", "-v"} & set(create)
    caps = [create[i + 1] for i, arg in enumerate(create) if arg == "--cap-add"]
    if role == "client":
        assert caps == ["NET_RAW", "SETUID", "SETGID", "KILL"]
    else:
        assert "NET_ADMIN" not in caps and "NET_RAW" not in caps
    assert lab.containers == ["owned-container-id"]


def test_lab_failed_create_does_not_claim_existing_container(docker_lab, monkeypatch):
    _, lab = docker_lab

    def fail(*args, **kwargs):
        raise RuntimeError("name conflict")

    monkeypatch.setattr(lab, "call", fail)
    with pytest.raises(RuntimeError):
        lab.create("client")
    assert lab.containers == []


@pytest.mark.parametrize("endpoint", ["tcp://127.0.0.1:2375", "ssh://remote"])
def test_lab_rejects_remote_engine_before_info(docker_lab, monkeypatch, endpoint):
    _, lab = docker_lab
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        value = (
            "context"
            if args == ("context", "show")
            else json.dumps([{"Endpoints": {"docker": {"Host": endpoint}}}])
        )
        return subprocess.CompletedProcess(args, 0, value, "")

    monkeypatch.setattr(lab, "call", fake)
    with pytest.raises(RuntimeError, match="로컬"):
        lab.preflight()
    assert len(calls) == 2


def test_lab_cleanup_only_owned_ids_and_continues_on_failure(docker_lab, monkeypatch):
    _, lab = docker_lab
    lab.containers = ["owned-a", "owned-b"]
    lab.network = "owned-net"
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, int(args[-1] == "owned-b"), "", "")

    monkeypatch.setattr(lab, "call", fake)
    assert lab.cleanup() == ["owned-b"]
    assert calls == [
        ("rm", "-f", "owned-b"),
        ("rm", "-f", "owned-a"),
        ("network", "rm", "owned-net"),
    ]


def test_lab_output_never_overwrites(docker_lab):
    module, lab = docker_lab
    with pytest.raises(FileExistsError):
        module.Lab(lab.output)


@pytest.mark.parametrize(
    "ready,ssh_status,capture_status",
    [
        (True, 0, 124),
        (True, 0, 0),
        (True, 255, 124),
        (True, 0, 1),
        (False, 0, 1),
    ],
)
def test_lab_capture_readiness_single_ssh_and_failure(
    docker_lab, monkeypatch, ready, ssh_status, capture_status
):
    module, lab = docker_lab
    lab.context = "local"
    calls = []

    class FakeCapture:
        returncode = None

        def __init__(self, command, stdout, stderr, env):
            assert command[-2:] == ["10", "1000"]
            stderr.write(b"listening on eth0\n" if ready else b"permission denied\n")
            stderr.flush()

        def poll(self):
            return None if ready else capture_status

        def wait(self, timeout):
            self.returncode = capture_status
            return capture_status

    def fake(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, ssh_status, "", "mock SSH")

    monkeypatch.setattr(module.subprocess, "Popen", FakeCapture)
    monkeypatch.setattr(lab, "call", fake)
    if ready and ssh_status == 0 and capture_status in (0, 124):
        lab.capture("owned-client", "192.0.2.2", "eth0")
    else:
        with pytest.raises(RuntimeError):
            lab.capture("owned-client", "192.0.2.2", "eth0")
    assert len(calls) == int(ready)
    if ready:
        assert calls[0] == (
            "exec",
            "--user",
            "lab",
            "--env",
            "HOME=/home/lab",
            "owned-client",
            "timeout",
            "15",
            "bash",
            "/opt/network/ssh_single_connect.sh",
            "192.0.2.2",
            "lab",
            "2222",
            "5",
        )


def test_lab_listen_probe_does_not_connect(docker_lab, monkeypatch):
    _, lab = docker_lab
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "LISTEN 0 128 *:2222", "")

    monkeypatch.setattr(lab, "call", fake)
    lab.wait_listener("owned-server")
    assert calls == [("exec", "owned-server", "ss", "-H", "-lnt", "sport = :2222")]


def test_lab_reads_ephemeral_public_key_as_owner(docker_lab, monkeypatch):
    _, lab = docker_lab
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "ssh-ed25519 mock\n", "")

    monkeypatch.setattr(lab, "call", fake)
    assert lab.read_public_key("owned-client") == "ssh-ed25519 mock\n"
    assert calls == [
        (
            "exec",
            "--user",
            "lab",
            "owned-client",
            "cat",
            "/home/lab/.ssh/id_ed25519.pub",
        )
    ]


def test_lab_empty_capture_is_not_success(docker_lab, monkeypatch):
    _, lab = docker_lab

    def fake(*args, **kwargs):
        if args[0] == "cp":
            (lab.output / "capture.pcap").write_bytes(b"mock-header-not-real-pcap")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(lab, "call", fake)
    with pytest.raises(RuntimeError, match="패킷 없음"):
        lab.preserve("owned-client")
    assert (lab.output / "capture.pcap").exists()


def test_lab_failed_evidence_copy_keeps_original_container(docker_lab, monkeypatch):
    _, lab = docker_lab
    lab.containers = ["owned-server", "owned-client"]
    lab.network = "owned-net"
    calls = []

    def fake(*args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, int(args[0] == "cp"), "", "")

    monkeypatch.setattr(lab, "call", fake)
    with pytest.raises(RuntimeError, match="pcap 확보 실패"):
        lab.preserve("owned-client")
    assert lab.cleanup() == ["owned-client", "owned-net"]
    assert ("rm", "-f", "owned-server") in calls
    assert ("rm", "-f", "owned-client") not in calls
    assert not any(call[:2] == ("network", "rm") for call in calls)


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
