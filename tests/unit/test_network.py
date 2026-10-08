"""실제 SSH 대신 격리된 PATH의 가짜 실행 파일로 네트워크 부작용 없이 검증한다."""

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest


@pytest.fixture
def sg_timeline(monkeypatch):
    directory = Path(__file__).resolve().parents[2] / "network"
    monkeypatch.syspath_prepend(str(directory))
    spec = importlib.util.spec_from_file_location(
        "sg_connection_timeline", directory / "sg_connection_timeline.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sg_event(event_id, kind, epoch, *, connection="A", sequence=0):
    # 합성 echo의 메타데이터만 사용한다. 실제 소켓·AWS·장비 시계로 폴백하지 않는다.
    identity, port = {"A": (1, 40000), "B": (2, 40001), "R": (3, 40002)}[connection]
    return [
        event_id,
        connection,
        identity,
        "192.0.2.1",
        port,
        "192.0.2.2",
        9000,
        sequence,
        kind,
        epoch,
        32 if sequence else 0,
    ]


def sg_times(**overrides):
    return {
        "start": "10",
        "end": "30",
        "change_start": "15",
        "api_complete": "16",
        "sg_confirmed": "17",
        "clock_error": "0.1",
        **overrides,
    }


def sg_baseline():
    return [
        sg_event(1, "socket_open", "10"),
        sg_event(2, "send", "11", sequence=1),
        sg_event(3, "server_receive", "11.1", sequence=1),
        sg_event(4, "response_receive", "11.2", sequence=1),
    ]


def sg_analyze(module, rows, **times):
    return module.analyze_events(waf_csv(module, rows), **sg_times(**times))


def test_sg_correlates_same_socket_post_change_and_separate_new_connection(sg_timeline):
    rows = sg_baseline() + [
        sg_event(5, "send", "18", sequence=2),
        sg_event(6, "server_receive", "18.1", sequence=2),
        sg_event(7, "response_receive", "18.2", sequence=2),
        sg_event(8, "socket_open", "19", connection="B"),
        sg_event(9, "timeout", "22", connection="B"),
    ]
    report = sg_analyze(sg_timeline, rows)
    assert report["connections"]["A"]["baseline_roundtrip_before_change_recorded"]
    assert report["connections"]["A"]["post_confirmation_roundtrip_sequences"] == [2]
    assert report["connections"]["B"]["post_confirmation_roundtrip_sequences"] == []
    assert "미확정" in report["sg_cause"]
    assert "별도 대조" in report["connections"]["A"]["observation"]


@pytest.mark.parametrize("kind", ["observed_established", "tcp_ack", "send", "response_receive"])
def test_sg_state_ack_send_or_delayed_response_does_not_prove_delivery(sg_timeline, kind):
    row = sg_event(5, kind, "18", sequence=2 if kind != "observed_established" else 0)
    report = sg_analyze(sg_timeline, sg_baseline() + [row])
    assert report["connections"]["A"]["post_confirmation_roundtrip_sequences"] == []
    assert "증거 부족" in report["connections"]["A"]["observation"]


@pytest.mark.parametrize("sent", ["14", "17", "17.199999999", "17.2"])
def test_sg_pre_change_send_and_clock_margin_not_counted_as_post_change(sg_timeline, sent):
    rows = sg_baseline() + [
        sg_event(5, "send", sent, sequence=2),
        sg_event(6, "server_receive", "18", sequence=2),
        sg_event(7, "response_receive", "19", sequence=2),
    ]
    assert (
        sg_analyze(sg_timeline, rows)["connections"]["A"]["post_confirmation_roundtrip_sequences"]
        == []
    )


def test_sg_reverse_order_duplicates_and_missing_evidence(sg_timeline):
    rows = sg_baseline()
    report = sg_analyze(sg_timeline, list(reversed(rows)) + [rows[0]])
    assert report["input_out_of_order"] and report["duplicate_event_count"] == 1
    assert len(report["connections"]["A"]["events"]) == 4
    assert sg_analyze(sg_timeline, [])["connections"] == {}
    without_open = sg_analyze(sg_timeline, rows[1:])
    assert not without_open["connections"]["A"]["baseline_roundtrip_before_change_recorded"]


@pytest.mark.parametrize("terminal", ["socket_close", "socket_reset"])
def test_sg_refuses_new_send_after_socket_termination(sg_timeline, terminal):
    rows = sg_baseline() + [sg_event(5, terminal, "18"), sg_event(6, "send", "19", sequence=2)]
    with pytest.raises(ValueError):
        sg_analyze(sg_timeline, rows)


def test_sg_nanosecond_send_interval_and_new_socket_creation(sg_timeline):
    rows = sg_baseline() + [
        sg_event(5, "send", "18", sequence=2),
        sg_event(6, "send", "18.000000001", sequence=3),
        sg_event(7, "socket_open", "19", connection="B"),
    ]
    report = sg_analyze(sg_timeline, rows)
    assert report["connections"]["A"]["minimum_send_interval_seconds"] == "0.000000001"
    assert report["connections"]["B"]["new_socket_after_confirmation_recorded"]
    assert report["connections"]["B"]["post_confirmation_roundtrip_sequences"] == []


def test_sg_write_failure_preserves_owned_partial_result(sg_timeline, tmp_path, monkeypatch):
    source, output = tmp_path / "events.csv", tmp_path / "report.json"
    source.write_text(waf_csv(sg_timeline, sg_baseline()), encoding="utf-8")

    def failing_dump(report, handle, **kwargs):
        handle.write('{"partial":')
        raise OSError("synthetic storage failure")

    monkeypatch.setattr(sg_timeline.json, "dump", failing_dump)
    with pytest.raises(OSError):
        sg_timeline.write_report(source, output, **sg_times())
    assert output.read_text() == '{"partial":'
    assert source.exists()


@pytest.mark.parametrize(
    "index,value",
    [
        (0, 0),
        (1, "C"),
        (2, "secret-token"),
        (3, "2001:db8::1"),
        (4, 0),
        (4, 65536),
        (6, "09000"),
        (7, 21),
        (8, "Authorization"),
        (9, "NaN"),
        (9, "31"),
        (10, 257),
    ],
)
def test_sg_rejects_invalid_or_sensitive_metadata(sg_timeline, index, value):
    row = sg_event(1, "send", "18", sequence=1)
    row[index] = value
    with pytest.raises(ValueError) as error:
        sg_analyze(sg_timeline, [row])
    assert "secret-token" not in str(error.value) and "Authorization" not in str(error.value)


@pytest.mark.parametrize(
    "violation",
    [
        "reconnect",
        "extra_open",
        "port_reuse",
        "socket_reuse",
        "other_server",
        "conflicting_id",
        "duplicate_stage",
        "size",
        "causality",
        "state_payload",
        "missing_sequence",
        "extra_field",
        "short_row",
    ],
)
def test_sg_rejects_ambiguous_connection_or_message_evidence(sg_timeline, violation):
    first = sg_event(1, "socket_open", "10")
    second = sg_event(2, "send", "18", sequence=1)
    rows = [first, second]
    if violation == "reconnect":
        second[2] = 2
    elif violation == "extra_open":
        second = sg_event(2, "socket_open", "18")
        rows[1] = second
    elif violation in {"port_reuse", "socket_reuse"}:
        second = sg_event(2, "socket_open", "18", connection="B")
        rows[1] = second
        second[4 if violation == "port_reuse" else 2] = first[4 if violation == "port_reuse" else 2]
    elif violation == "other_server":
        second = sg_event(2, "socket_open", "18", connection="B")
        rows[1] = second
        second[5] = "192.0.2.3"
    elif violation == "conflicting_id":
        second[0] = 1
    elif violation == "duplicate_stage":
        rows.append(sg_event(3, "send", "19", sequence=1))
    elif violation == "size":
        rows.append(sg_event(3, "server_receive", "19", sequence=1))
        rows[-1][10] = 64
    elif violation == "causality":
        rows.append(sg_event(3, "server_receive", "17", sequence=1))
    elif violation == "state_payload":
        first[7] = 1
        first[10] = 32
    elif violation == "missing_sequence":
        second[7] = 0
    elif violation == "extra_field":
        second.append("secret-token")
    elif violation == "short_row":
        second.pop()
    with pytest.raises(ValueError):
        sg_analyze(sg_timeline, rows)


@pytest.mark.parametrize(
    "times",
    [
        {"end": "131"},
        {"change_start": "18"},
        {"api_complete": "18"},
        {"clock_error": "5.1"},
        {"start": "1e1"},
    ],
)
def test_sg_rejects_invalid_control_times_and_observation_bounds(sg_timeline, times):
    with pytest.raises(ValueError):
        sg_analyze(sg_timeline, [], **times)


def test_sg_capacity_header_and_writer_preservation(sg_timeline, waf_timeline, tmp_path):
    with pytest.raises(ValueError):
        sg_timeline.analyze_events("x" * (sg_timeline.MAX_BYTES + 1), **sg_times())
    with pytest.raises(ValueError):
        sg_analyze(sg_timeline, [sg_event(1, "socket_open", "10")] * (sg_timeline.MAX_ROWS + 1))
    with pytest.raises(ValueError):
        sg_timeline.analyze_events("Authorization,secret-token", **sg_times())
    source, output, packets = (
        tmp_path / "events.csv",
        tmp_path / "report.json",
        tmp_path / "tcp.csv",
    )
    source.write_text(waf_csv(sg_timeline, sg_baseline()), encoding="utf-8")
    packets.write_text(waf_csv(waf_timeline, [waf_packet()]), encoding="utf-8")
    sg_timeline.write_report(source, output, packets=packets, **sg_times())
    report = json.loads(output.read_text(encoding="utf-8"))
    assert len(report["source_sha256"]) == 64 and len(report["packet_csv_sha256"]) == 64
    assert report["tcp"]["packet_count"] == 1
    original = output.read_bytes()
    with pytest.raises(FileExistsError):
        sg_timeline.write_report(source, output, **sg_times())
    assert output.read_bytes() == original
    packets.write_text("secret-token")
    fresh = tmp_path / "fresh.json"
    with pytest.raises(ValueError):
        sg_timeline.write_report(source, fresh, packets=packets, **sg_times())
    assert not fresh.exists()


def test_sg_cli_failure_preserves_partial_output_without_echo_or_network(
    sg_timeline, tmp_path, monkeypatch, capsys
):
    source, output = tmp_path / "secret-token.csv", tmp_path / "output.json"
    source.write_text("Authorization,secret-token")
    argv = ["timeline", str(source), str(output)]
    for key, value in sg_times().items():
        argv.extend(["--" + key.replace("_", "-"), value])
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as error:
        sg_timeline.main()
    assert error.value.code == 2 and "secret-token" not in capsys.readouterr().err
    assert not output.exists()


@pytest.fixture
def waf_timeline():
    path = Path(__file__).resolve().parents[2] / "network/waf_packet_timeline.py"
    spec = importlib.util.spec_from_file_location("waf_packet_timeline", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def waf_csv(module, rows):
    return ",".join(module.FIELDS) + "\n" + "\n".join(",".join(map(str, row)) for row in rows)


def waf_packet(epoch="10.000000001", stream="0", flags=("0", "1", "0", "0")):
    return [epoch, stream, "192.0.2.1", "40000", "192.0.2.2", "443", *flags]


@pytest.mark.parametrize(
    "flags",
    [("0", "1", "0", "0"), ("0", "1", "1", "0"), ("0", "1", "0", "1"), ("0", "1", "1", "1")],
)
def test_waf_timeline_flags_never_infer_http_or_waf(waf_timeline, flags):
    report = waf_timeline.analyze_csv(
        waf_csv(waf_timeline, [waf_packet(flags=flags)]), start="10", end="11"
    )
    connection = report["streams"]["0"]
    assert connection["fin_observed"] == (flags[2] == "1")
    assert connection["rst_observed"] == (flags[3] == "1")
    assert connection["packets"][0]["source"] == "192.0.2.1:40000"
    assert report["waf_cause"] == "미확정"
    assert "판정 불가" in report["http_status"]
    if flags[2:] == ("0", "0"):
        assert "관측 구간 내 종료 없음" in connection["observation"]


def test_waf_timeline_keeps_reverse_direction_retransmissions_and_decimal_time(waf_timeline):
    syn = waf_packet(epoch="10", flags=("1", "0", "0", "0"))
    reply = waf_packet(epoch="10.000000001", flags=("1", "1", "0", "0"))
    reply[2:6] = ["192.0.2.2", "443", "192.0.2.1", "40000"]
    report = waf_timeline.analyze_csv(
        waf_csv(waf_timeline, [reply, syn, syn]), start="10", end="11"
    )
    stream = report["streams"]["0"]
    assert stream["input_out_of_order"]
    assert len(stream["packets"]) == 3
    assert stream["packets"][2]["offset_seconds"] == "0.000000001"
    assert Decimal(stream["packets"][2]["epoch"]) - Decimal(
        stream["packets"][0]["epoch"]
    ) == Decimal("0.000000001")
    assert "자동 확정하지 않음" in report["handshake"]


def test_waf_timeline_new_connection_not_reuse_and_missing_packets(waf_timeline):
    first, second = waf_packet(), waf_packet(stream="1")
    second[3] = "40001"
    report = waf_timeline.analyze_csv(waf_csv(waf_timeline, [first, second]), start="10", end="11")
    assert len(report["streams"]) == 2
    empty = waf_timeline.analyze_csv(waf_csv(waf_timeline, []), start="10", end="11")
    assert empty["packet_count"] == 0 and empty["streams"] == {}
    assert empty["waf_cause"] == "미확정"


@pytest.mark.parametrize(
    "index,value",
    [
        (0, "NaN"),
        (0, "9"),
        (0, "12"),
        (0, "1e1"),
        (1, "-1"),
        (2, "2001:db8::1"),
        (2, "secret-token"),
        (3, "0"),
        (3, "65536"),
        (3, "0443"),
        (6, "2"),
    ],
)
def test_waf_timeline_rejects_bad_fields_without_echo(waf_timeline, index, value):
    packet = waf_packet()
    packet[index] = value
    with pytest.raises(ValueError) as error:
        waf_timeline.analyze_csv(waf_csv(waf_timeline, [packet]), start="10", end="11")
    assert "secret-token" not in str(error.value)


@pytest.mark.parametrize(
    "violation",
    [
        "extra_column",
        "short_row",
        "extra_row_field",
        "changed_tuple",
        "backward_window",
        "oversize",
        "rows",
    ],
)
def test_waf_timeline_rejects_ambiguous_or_unbounded_evidence(waf_timeline, violation):
    raw = waf_csv(waf_timeline, [waf_packet()])
    start, end = "10", "11"
    if violation == "extra_column":
        raw = raw.replace("tcp.flags.reset\n", "tcp.flags.reset,Authorization\n")
    elif violation == "short_row":
        raw = ",".join(waf_timeline.FIELDS) + "\n10,0"
    elif violation == "extra_row_field":
        raw += ",secret-token"
    elif violation == "changed_tuple":
        changed = waf_packet()
        changed[3] = "40001"
        raw = waf_csv(waf_timeline, [waf_packet(), changed])
    elif violation == "backward_window":
        end = start
    elif violation == "oversize":
        raw = "x" * (waf_timeline.MAX_BYTES + 1)
    else:
        raw = waf_csv(waf_timeline, [waf_packet()] * (waf_timeline.MAX_ROWS + 1))
    with pytest.raises(ValueError):
        waf_timeline.analyze_csv(raw, start=start, end=end)


def test_waf_timeline_writer_preserves_existing_and_invalid_input_has_no_output(
    waf_timeline, tmp_path
):
    source, output = tmp_path / "tcp.csv", tmp_path / "report.json"
    source.write_text(waf_csv(waf_timeline, [waf_packet()]))
    output.write_text("existing")
    with pytest.raises(FileExistsError):
        waf_timeline.write_report(source, output, start="10", end="11")
    assert output.read_text() == "existing"
    fresh = tmp_path / "fresh.json"
    source.write_text("Authorization,secret-token")
    with pytest.raises(ValueError):
        waf_timeline.write_report(source, fresh, start="10", end="11")
    assert not fresh.exists()
    source.write_text(waf_csv(waf_timeline, [waf_packet()]))
    waf_timeline.write_report(source, fresh, start="10", end="11")
    assert json.loads(fresh.read_text(encoding="utf-8"))["packet_count"] == 1


def test_waf_timeline_cli_failure_does_not_echo_raw_or_invoke_tools(
    waf_timeline, tmp_path, monkeypatch, capsys
):
    source = tmp_path / "secret-token.csv"
    source.write_text("Authorization,secret-token")
    output = tmp_path / "fresh.json"
    monkeypatch.setattr(
        "sys.argv", ["timeline", str(source), str(output), "--start", "10", "--end", "11"]
    )
    with pytest.raises(SystemExit) as error:
        waf_timeline.main()
    assert error.value.code == 2
    assert "secret-token" not in capsys.readouterr().err
    assert not output.exists()


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
@pytest.mark.parametrize("spray", [False, True])
def test_hydra_capture_requires_ready_and_real_log_evidence(
    hydra_lab, monkeypatch, ready, code, state, failures, accepted, spray
):
    host, _, lab = hydra_lab
    if spray:
        lab.accounts = ["spraylab2", "spraylab1"]
        lab.candidates = 1
        lab.interval = 2
        lab.max_attempts = 2
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
        spec = json.loads(kwargs["data"])
        assert spec["target"] == "192.0.2.2"
        assert "password" not in spec
        if spray:
            assert spec["accounts"] == ["spraylab2", "spraylab1"]
            assert spec["candidates"] == 1 and spec["interval"] == 2
            assert spec["max_attempts"] == 2
        else:
            assert "accounts" not in spec
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


WEB_SCRIPT = SCRIPT.with_name("web_dir_scan.sh")


@pytest.fixture
def web_plan(web_sequence, web_scan):
    """기존 격리 도구에 가상 초 시계를 결합한다. 요청 간 대기는 실제로 수행하지 않는다.

    요청별 시각·argv만 합성 로그로 연결하며 실제 서버 응답이나 운영 수집 성공을 가정하지 않는다.
    """
    run, evidence, args_file, _, _, bash_path = web_scan
    fake_bin = args_file.parent / "web fake bin"
    Path(str(args_file) + ".clock").write_text("0\n", newline="\n")
    # 감시 루프가 빈 파일을 읽지 않도록 같은 디렉터리에서 완성한 값을 rename으로 공개한다.
    # 단일 writer(간격 대기 또는 curl)만 활성화되며 실패하면 기존 시각을 보존하고 종료한다.
    clock_set = fake_bin / "clock-set"
    clock_set.write_text(
        "#!/bin/bash\nset -euo pipefail\n"
        'pending="$MOCK_ARGS.clock.$$"\n'
        "trap '/usr/bin/rm -f -- \"$pending\"' EXIT\n"
        ': > "$pending"\n'
        'if [[ $MOCK_MODE == atomic_probe ]]; then date +%s >> "$MOCK_ARGS.reads"; fi\n'
        'printf "%s\\n" "$1" > "$pending"\n'
        'if [[ $MOCK_MODE == atomic_probe ]]; then date +%s >> "$MOCK_ARGS.reads"; fi\n'
        '/usr/bin/mv -f -- "$pending" "$MOCK_ARGS.clock"\n',
        newline="\n",
    )
    clock_set.chmod(0o755)
    (fake_bin / "date").write_text(
        "#!/bin/bash\nif [[ $1 == +%s ]]; then\n"
        ' n=0; if [[ -f $MOCK_ARGS.clock ]]; then read -r n < "$MOCK_ARGS.clock"; fi\n'
        ' printf "%s\\n" "$n"\nelse exec /usr/bin/date "$@"; fi\n',
        newline="\n",
    )
    (fake_bin / "sleep").write_text(
        "#!/bin/bash\nif [[ $1 == 0.1 ]]; then exec /usr/bin/sleep 0.001; fi\n"
        "[[ $MOCK_MODE != sleep_failure ]] || exit 42\n"
        'n=0; if [[ -f $MOCK_ARGS.clock ]]; then read -r n < "$MOCK_ARGS.clock"; fi\n'
        'exec clock-set "$((n + $1))"\n',
        newline="\n",
    )
    curl = fake_bin / "curl"
    original = curl.read_text()
    curl.write_text(
        original.replace(
            "printf '%s' \"$code\"",
            'date +%s >> "$MOCK_ARGS.times"\n'
            "if [[ $n == 2 ]]; then\n"
            " case $MOCK_MODE in\n"
            "  deadline) clock-set 300 || exit; "
            'printf "%s\\n" "$$" > "$MOCK_PID"; exec /usr/bin/sleep 30 ;;\n'
            '  signal) printf "%s\\n" "$$" > "$MOCK_PID"; '
            'kill -TERM "$PPID"; exec /usr/bin/sleep 30 ;;\n'
            " esac\nfi\n"
            "printf '%s' \"$code\"",
        ),
        newline="\n",
    )

    def invoke(paths, codes, *, interval=0, mode="ok", limit=205):
        result = run(
            [
                "--url",
                "http://127.0.0.1:8080",
                "--paths",
                ",".join(paths),
                "--interval",
                str(interval),
                "--max-runtime",
                str(limit),
                "--evidence",
                bash_path(evidence),
                "--execute",
            ],
            codes=" ".join(map(str, codes)),
            mode=mode,
        )
        summary = dict(line.split("=", 1) for line in evidence.read_text().splitlines())
        arguments = web_sequence[1]()
        urls = [arg for arg in arguments if arg.startswith("http://")]
        times_file = Path(str(args_file) + ".times")
        times = list(map(int, times_file.read_text().splitlines())) if times_file.exists() else []
        return result, summary, urls, times

    return invoke


def web_plan_logs(paths, codes, times):
    """모의 관측값을 계약 파서 입력으로 변환한다. 탐지 집계·정규화는 구현하지 않는다."""
    from contracts.events import NginxAccessLogEvent

    logs = []
    for path, code, second in zip(paths, codes, times, strict=True):
        timestamp = datetime.fromtimestamp(1790899200 + second, UTC).strftime(
            "%d/%b/%Y:%H:%M:%S %z"
        )
        line = (
            f'198.51.100.77 - - [{timestamp}] "GET /{path} HTTP/1.1" {code} 0 "-" "mock" 0.001 "-"'
        )
        event = NginxAccessLogEvent.parse_line(line)
        assert event is not None
        logs.append(event)
    return logs


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_web_plan_thresholds_use_existing_rule(web_plan, delta):
    from detection.rules import WEB_SCAN_PATH_THRESHOLD, evaluate_web_rules

    paths = ["admin", "login", "dashboard", "api", "backup", "config"]
    paths = paths[: WEB_SCAN_PATH_THRESHOLD + delta]
    codes = [404] * len(paths)
    result, summary, urls, times = web_plan(paths, codes)
    assert result.returncode == 0, result.stderr
    assert urls == ["http://127.0.0.1:8080/" + path for path in paths]
    assert summary["attempted_requests"] == str(len(paths))
    assert evaluate_web_rules(web_plan_logs(paths, codes, times)) == (
        (True, "WEB_DIRECTORY_SCANNING") if delta >= 0 else (False, None)
    )


@pytest.mark.parametrize("fail_delta", [-1, 0, 1])
def test_web_plan_failure_paths_are_distinct_and_status_dependent(web_plan, fail_delta):
    from detection.rules import (
        WEB_SCAN_FAILURE_THRESHOLD,
        WEB_SCAN_PATH_THRESHOLD,
        evaluate_web_rules,
    )

    paths = ["admin", "login", "dashboard", "api", "backup", "config"][:WEB_SCAN_PATH_THRESHOLD]
    failure_count = WEB_SCAN_FAILURE_THRESHOLD + fail_delta
    codes = [401, 403, 404, 401][:failure_count] + [200] * (len(paths) - failure_count)
    result, _, _, times = web_plan(paths, codes)
    assert result.returncode == 0
    assert evaluate_web_rules(web_plan_logs(paths, codes, times))[0] == (fail_delta >= 0)


@pytest.mark.parametrize(
    "paths,codes,expected",
    [
        (["admin", "login", "dashboard", "api", "health"], [404] * 5, False),
        (["admin", "admin", "admin", "login", "dashboard"], [404] * 5, False),
        (
            ["admin", "login", "dashboard", "api", "backup", "admin", "admin"],
            [404, 200, 301, 302, 500, 401, 403],
            False,
        ),
        (
            ["admin", "login", "dashboard", "api", "backup", "admin"],
            [200, 401, 403, 301, 500, 404],
            True,
        ),
        (
            ["health", "images", "static", "assets", "robots.txt", "sitemap.xml", "uploads"],
            [404] * 7,
            False,
        ),
    ],
)
def test_web_plan_noise_and_duplicates_preserve_request_order(web_plan, paths, codes, expected):
    from detection.rules import evaluate_web_rules

    result, summary, urls, times = web_plan(paths, codes)
    assert result.returncode == 0
    assert [url.rsplit("/", 1)[-1] for url in urls] == paths
    assert summary["observed_statuses"] == str(len(paths))
    assert evaluate_web_rules(web_plan_logs(paths, codes, times))[0] == expected


@pytest.mark.parametrize("interval,expected", [(0, True), (2, True), (3, False), (11, False)])
def test_web_plan_intervals_use_virtual_time(web_plan, interval, expected):
    from detection.rules import evaluate_web_rules

    paths = ["admin", "login", "dashboard", "api", "backup"]
    codes = [404] * len(paths)
    result, _, _, times = web_plan(paths, codes, interval=interval)
    assert result.returncode == 0
    assert times == [i * interval for i in range(len(paths))]
    assert evaluate_web_rules(web_plan_logs(paths, codes, times))[0] == expected


@pytest.mark.parametrize("offset,expected", [(-1, True), (0, True), (1, False)])
def test_web_plan_exact_window_boundary_from_observations(web_plan, offset, expected):
    from detection.rules import WEB_SCAN_WINDOW_SECONDS, evaluate_web_rules

    paths = ["admin", "login", "dashboard", "api", "backup"]
    codes = [404] * len(paths)
    result, _, _, times = web_plan(paths, codes)
    assert result.returncode == 0
    # 마지막 응답의 가상 지연만 바꿔 경계 양쪽을 비교한다. 실제 sleep과 운영 SLA 주장을 피한다.
    times[-1] += WEB_SCAN_WINDOW_SECONDS + offset
    assert evaluate_web_rules(web_plan_logs(paths, codes, times))[0] == expected


def test_web_plan_clock_readers_never_see_pending_write(web_plan, web_scan):
    """빈 임시 파일과 완성된 임시 파일 단계마다 별도 reader를 실행해 공개 전 값을 확인한다."""
    paths = ["admin", "login", "dashboard", "api", "backup"]
    result, _, _, times = web_plan(paths, [404] * len(paths), interval=3, mode="atomic_probe")
    assert result.returncode == 0, result.stderr
    assert times == [0, 3, 6, 9, 12]
    reads = Path(str(web_scan[2]) + ".reads").read_text().splitlines()
    assert reads == ["0", "0", "3", "3", "6", "6", "9", "9"]
    assert not list(web_scan[2].parent.glob("argv.txt.clock.*"))


def test_web_plan_normalization_and_collection_gap(web_plan):
    from collector.cw_processor import NGINX_SUBSCRIPTION_FILTER_SPEC, matches_subscription_filter
    from detection.rules import evaluate_web_rules

    paths = ["admin", "login", "dashboard", "api", "backup", "admin"]
    codes = [401, 403, 404, 200, 302, 404]
    result, _, _, times = web_plan(paths, codes)
    assert result.returncode == 0
    logs = web_plan_logs(paths, codes, times)
    assert evaluate_web_rules(logs) == (True, "WEB_DIRECTORY_SCANNING")
    filtered = [
        event
        for event in logs
        if matches_subscription_filter(
            event.raw_message, NGINX_SUBSCRIPTION_FILTER_SPEC["filter_pattern"]
        )
    ]
    assert evaluate_web_rules(filtered) == (False, None)
    # 경로 입력은 제한된 합성 후보만 허용한다. 인코딩·쿼리 표현 차이는 파서 경계에서만 검증한다.
    variants = ["admin", "%61dmin", "%2561dmin", "admin?sample=1", "admin"]
    assert evaluate_web_rules(web_plan_logs(variants, [404] * 5, [0] * 5)) == (False, None)


@pytest.mark.parametrize(
    "options",
    [
        ["--paths", ""],
        ["--paths", "admin,"],
        ["--paths", "admin,,login"],
        ["--paths", "../admin"],
        ["--paths", "admin?token=MOCK-SECRET"],
        ["--paths", "Authorization: MOCK-SECRET"],
        ["--paths", "unknown"],
        ["--paths", ",".join(["admin"] * 21)],
        ["--paths", "a" * 513],
        ["--paths", "admin", "--candidates", "1"],
        ["--paths", "admin", "--tool", "gobuster"],
        ["--interval", "1", "--tool", "gobuster"],
        ["--interval", "-1"],
        ["--interval", "12"],
        ["--interval", "0.5"],
        ["--max-runtime", "0"],
        ["--max-runtime", "301"],
        ["--max-runtime", "1e2"],
        ["--paths", "admin,login", "--interval", "11", "--max-runtime", "11"],
        ["--MOCK-SECRET"],
    ],
)
def test_web_plan_invalid_inputs_fail_before_side_effects(web_scan, options):
    run, evidence, args_file, _, _, bash_path = web_scan
    result = run(
        ["--url", "http://127.0.0.1", "--evidence", bash_path(evidence), *options, "--execute"]
    )
    assert result.returncode == 2
    assert not evidence.exists() and not args_file.exists()
    assert "MOCK-SECRET" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "mode,state,code,attempted",
    [
        ("deadline", "timeout", 124, 2),
        ("signal", "interrupted", 143, 2),
        ("sleep_failure", "tool_error", 42, 1),
    ],
)
def test_web_plan_stops_and_cleans_owned_curl(
    web_plan, web_sequence, web_scan, mode, state, code, attempted
):
    result, summary, urls, _ = web_plan(
        ["admin", "login", "backup"], [404] * 3, mode=mode, interval=1
    )
    assert result.returncode == code
    assert_web_distribution(
        summary, [0, 0, 0, 0, 1, 0], planned=3, attempted=attempted, state=state, code=code
    )
    assert len(urls) == attempted
    if web_scan[4].exists():
        assert not web_sequence[3]()
    temp = Path(str(web_scan[2]) + ".temp").read_text().strip()
    assert not web_sequence[2](temp).exists()


@pytest.fixture
def web_scan(tmp_path, bash):
    """실제 네트워크 도구가 PATH로 섞이지 않도록 모의 실행 파일만 허용한다."""
    fake_bin = tmp_path / "web fake bin"
    fake_bin.mkdir()
    for utility in ("date", "mktemp", "chmod", "rm", "rmdir", "sleep"):
        shim = fake_bin / utility
        shim.write_text(f'#!/bin/bash\nexec /usr/bin/{utility} "$@"\n', newline="\n")
        shim.chmod(0o755)
    curl = fake_bin / "curl"
    curl.write_text(
        r"""#!/bin/bash
printf '%s\n' "$@" >> "$MOCK_ARGS"
n=0
if [[ -f $MOCK_COUNT ]]; then read -r n < "$MOCK_COUNT"; fi
((n += 1))
printf '%s\n' "$n" > "$MOCK_COUNT"
case $MOCK_MODE in timeout) exit 28 ;; connection) exit 7 ;; esac
read -r -a codes <<< "$MOCK_CODES"
printf '%s' "${codes[n-1]:-404}"
""",
        newline="\n",
    )
    curl.chmod(0o755)
    gobuster = fake_bin / "gobuster"
    gobuster.write_text(
        r"""#!/bin/bash
printf '%s\n' "$@" >> "$MOCK_ARGS"
printf '%s\n' "$$" > "$MOCK_PID"
case $MOCK_MODE in
  connection) exit 1 ;;
  interrupt) kill -TERM "$PPID"; /usr/bin/sleep 1; exit 0 ;;
  hang) trap '' TERM; while :; do /usr/bin/sleep 0.1; done ;;
esac
printf '/admin (Status: 200)\n/login (Status: 301)\n/backup (Status: 302)\n/private (Status: 403)\n'
""",
        newline="\n",
    )
    gobuster.chmod(0o755)
    args_file = tmp_path / "argv.txt"
    count_file = tmp_path / "count.txt"
    pid_file = tmp_path / "pid.txt"
    evidence = tmp_path / "evidence.txt"

    def bash_path(path):
        value = path.as_posix()
        return f"/{value[0].lower()}{value[2:]}" if value[1:3] == ":/" else value

    def run(args=None, *, mode="ok", codes="200 301 302 403 404", missing=None):
        if missing:
            (fake_bin / missing).unlink(missing_ok=True)
        args = args if args is not None else ["--url", "http://127.0.0.1:8080"]
        env = os.environ.copy()
        for name in ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"):
            env.pop(name, None)
        env.update(
            FAKE_BIN=bash_path(fake_bin),
            MOCK_ARGS=bash_path(args_file),
            MOCK_COUNT=bash_path(count_file),
            MOCK_PID=bash_path(pid_file),
            MOCK_MODE=mode,
            MOCK_CODES=codes,
            MSYS_NO_PATHCONV="1",
        )
        return subprocess.run(
            [
                bash,
                "--noprofile",
                "--norc",
                "-c",
                'cd "$FAKE_BIN" || exit; export PATH="$PWD"; '
                'exec /bin/bash --noprofile --norc "$@"',
                "web-test",
                bash_path(WEB_SCRIPT),
                *args,
            ],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=15,
            check=False,
        )

    return run, evidence, args_file, count_file, pid_file, bash_path


def test_web_dry_run_and_execute_gate(web_scan):
    run, evidence, args_file, _, _, bash_path = web_scan
    base = ["--url", "http://127.0.0.1:8080", "--evidence", bash_path(evidence)]
    result = run(base)
    assert result.returncode == 0 and "dry-run" in result.stdout
    assert not args_file.exists() and not evidence.exists()
    result = run([*base, "--execute", "--candidates", "1"])
    assert result.returncode == 0, result.stderr
    assert evidence.exists() and args_file.exists()
    assert "attempted_requests=1" in evidence.read_text()


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "https://[::1]:443/",
    ],
)
def test_web_loopback_urls_allowed(web_scan, url):
    run, _, args_file, _, _, _ = web_scan
    result = run(["--url", url])
    assert result.returncode == 0 and "dry-run" in result.stdout
    assert not args_file.exists()


@pytest.mark.parametrize(
    "url",
    [
        "http://example.org:80",
        "http://localhost:80",
        "http://10.0.0.1:80",
        "ftp://127.0.0.1",
        "http://user@127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:080",
        "http://127.0.0.1?x=1",
        "http://127.0.0.1#part",
        "http://127.0.0.1/admin",
        "http://127.0.0.1;touch INJECTED",
        "http://127.0.0.1/$(touch INJECTED)",
        "http://127.0.0.1\\@example.org",
        "http://127.0.0.1%2f.example.org",
    ],
)
def test_web_bad_urls_never_invoke_tools(web_scan, url):
    run, _, args_file, _, _, _ = web_scan
    result = run(["--url", url, "--execute"])
    assert result.returncode == 2, result.stderr
    assert not args_file.exists()
    assert not (args_file.parent / "web fake bin" / "INJECTED").exists()


@pytest.mark.parametrize(
    "option,value",
    [
        ("--candidates", "0"),
        ("--candidates", "21"),
        ("--concurrency", "0"),
        ("--concurrency", "5"),
        ("--timeout", "0"),
        ("--timeout", "11"),
        ("--candidates", "01"),
        ("--timeout", "1;id"),
    ],
)
def test_web_limits_reject_before_tools(web_scan, option, value):
    run, _, args_file, _, _, _ = web_scan
    result = run(["--url", "http://127.0.0.1", option, value, "--execute"])
    assert result.returncode == 2
    assert not args_file.exists()


def test_web_curl_statuses_and_safe_argv(web_scan):
    run, evidence, args_file, count_file, _, bash_path = web_scan
    result = run(
        [
            "--url",
            "http://127.0.0.1:8080",
            "--candidates",
            "5",
            "--evidence",
            bash_path(evidence),
            "--execute",
        ]
    )
    assert result.returncode == 0, result.stderr
    assert count_file.read_text().strip() == "5"
    output = evidence.read_text()
    for code in (200, 301, 302, 403, 404):
        assert f"http_{code}=1" in output
    assert "state=completed" in output and "exit_code=0" in output
    argv = args_file.read_text().splitlines()
    assert "--max-time" in argv and "--noproxy" in argv and "--output" in argv
    assert "http://127.0.0.1:8080/admin" in argv
    assert "--data" not in argv and "--location" not in argv


@pytest.mark.parametrize("missing", ["curl", "gobuster"])
def test_web_missing_tool_records_failure(web_scan, missing):
    run, evidence, args_file, _, _, bash_path = web_scan
    result = run(
        [
            "--url",
            "http://127.0.0.1",
            "--tool",
            missing,
            "--evidence",
            bash_path(evidence),
            "--execute",
        ],
        missing=missing,
    )
    assert result.returncode == 127
    assert "state=tool_missing" in evidence.read_text()
    assert not args_file.exists()


@pytest.mark.parametrize(
    "mode,state,code", [("timeout", "timeout", 124), ("connection", "connection_failure", 7)]
)
def test_web_curl_failure_classification(web_scan, mode, state, code):
    run, evidence, _, _, _, bash_path = web_scan
    result = run(
        ["--url", "http://127.0.0.1", "--evidence", bash_path(evidence), "--execute"], mode=mode
    )
    assert result.returncode == code
    assert f"state={state}" in evidence.read_text()


def test_web_gobuster_statuses_and_owned_temp_cleanup(web_scan):
    run, evidence, args_file, _, pid_file, bash_path = web_scan
    result = run(
        [
            "--url",
            "http://127.0.0.1:8080",
            "--tool",
            "gobuster",
            "--candidates",
            "5",
            "--concurrency",
            "4",
            "--timeout",
            "1",
            "--evidence",
            bash_path(evidence),
            "--execute",
        ]
    )
    assert result.returncode == 0, result.stderr
    output = evidence.read_text()
    assert "planned_requests=5" in output and "attempted_requests=unknown" in output
    for code in (200, 301, 302, 403):
        assert f"http_{code}=1" in output
    assert "http_404=0" in output
    argv = args_file.read_text().splitlines()
    wordlist = Path(argv[argv.index("-w") + 1])
    assert not wordlist.exists()
    assert "4" in argv and "1s" in argv and "--status-codes-blacklist" not in argv
    assert argv[argv.index("-b") + 1] == ""
    assert pid_file.exists()


def test_web_existing_evidence_is_preserved(web_scan):
    run, evidence, args_file, _, _, bash_path = web_scan
    evidence.write_text("keep original")
    result = run(["--url", "http://127.0.0.1", "--evidence", bash_path(evidence), "--execute"])
    assert result.returncode == 2
    assert evidence.read_text() == "keep original"
    assert not args_file.exists()


def test_web_gobuster_interrupt_cleans_its_child(web_scan, bash):
    run, evidence, args_file, _, pid_file, bash_path = web_scan
    result = run(
        [
            "--url",
            "http://127.0.0.1",
            "--tool",
            "gobuster",
            "--evidence",
            bash_path(evidence),
            "--execute",
        ],
        mode="interrupt",
    )
    assert result.returncode == 143, result.stderr
    assert "state=interrupted" in evidence.read_text()
    argv = args_file.read_text().splitlines()
    assert not Path(argv[argv.index("-w") + 1]).exists()
    alive = subprocess.run(
        [bash, "-c", 'kill -0 "$1" 2>/dev/null', "check", pid_file.read_text().strip()],
        capture_output=True,
        timeout=3,
        check=False,
    )
    assert alive.returncode != 0


def test_web_gobuster_timeout_kills_stubborn_owned_child(web_scan, bash):
    run, evidence, args_file, _, pid_file, bash_path = web_scan
    result = run(
        [
            "--url",
            "http://127.0.0.1",
            "--tool",
            "gobuster",
            "--candidates",
            "1",
            "--timeout",
            "1",
            "--evidence",
            bash_path(evidence),
            "--execute",
        ],
        mode="hang",
    )
    assert result.returncode == 124, result.stderr
    assert "state=timeout" in evidence.read_text()
    argv = args_file.read_text().splitlines()
    assert not Path(argv[argv.index("-w") + 1]).exists()
    alive = subprocess.run(
        [bash, "-c", 'kill -0 "$1" 2>/dev/null', "check", pid_file.read_text().strip()],
        capture_output=True,
        timeout=3,
        check=False,
    )
    assert alive.returncode != 0


def test_web_bash_syntax(bash):
    result = subprocess.run([bash, "-n", WEB_SCRIPT.as_posix()], capture_output=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.fixture
def web_sequence(web_scan, bash):
    """연속 응답과 실패를 고정하며 기존 격리 PATH를 재사용해 실제 도구 폴백을 막는다.

    !숫자는 모의 종료 코드이고 나머지는 HTTP 코드다. NUL 구분 argv는 빈 인자와
    공백·메타문자 경계를 보존한다. 실패한 테스트도 자신이 만든 PID만 회수한다.
    """
    run, evidence, args_file, count_file, pid_file, bash_path = web_scan
    fake_bin = args_file.parent / "web fake bin"
    (fake_bin / "curl").write_text(
        r"""#!/bin/bash
printf '%s\0' "$@" >> "$MOCK_ARGS"
n=0
if [[ -f $MOCK_COUNT ]]; then read -r n < "$MOCK_COUNT"; fi
((n += 1))
printf '%s\n' "$n" > "$MOCK_COUNT"
printf 'Authorization: Bearer MOCK-TOKEN; password=MOCK-PASSWORD; MOCK-BODY\n' >&2
read -r -a codes <<< "$MOCK_CODES"
code=${codes[n-1]:-404}
case $code in '!') exit 99 ;; '!'*) exit "${code:1}" ;; esac
printf '%s' "$code"
""",
        newline="\n",
    )
    (fake_bin / "gobuster").write_text(
        r"""#!/bin/bash
printf '%s\0' "$@" >> "$MOCK_ARGS"
printf '%s\n' "$$" > "$MOCK_PID"
while (($#)); do
  if [[ $1 == -w ]]; then wordlist=$2; break; fi
  shift
done
mapfile -t words < "$wordlist"
printf '%s\n' "${words[@]}" > "$MOCK_ARGS.words"
printf 'MOCK-BODY password=MOCK-PASSWORD Authorization: Bearer MOCK-TOKEN\n'
printf 'diagnostic (Status: 404)\n'
printf 'diagnostic (Status: 200)\n/unexpected (Status: 200)\n/admin (Status: 404)\n'
read -r -a codes <<< "$MOCK_CODES"
i=0
for code in "${codes[@]}"; do
  case $code in '!'*) exit "${code:1}" ;; esac
  case $code in
    200|301|302|403) printf '/%s (Status: %s) [Size: 77]\n' "${words[i]}" "$code" ;;
  esac
  ((i += 1))
done
case $MOCK_MODE in
  partial_int) kill -INT "$PPID"; exec /usr/bin/sleep 30 ;;
  partial_interrupt) kill -TERM "$PPID"; exec /usr/bin/sleep 30 ;;
  partial_hang) trap '' TERM; exec /usr/bin/sleep 30 ;;
esac
""",
        newline="\n",
    )
    # 소유 임시 경로를 기록하므로 Windows에서도 /tmp 경로의 잘못된 존재 판정을 피한다.
    (fake_bin / "mktemp").write_text(
        "#!/bin/bash\n"
        'directory=$(/usr/bin/mktemp -d "$MOCK_ARGS temp ; literal.XXXXXX") || exit\n'
        'printf "%s\\n" "$directory" > "$MOCK_ARGS.temp"\n'
        'printf "%s\\n" "$directory"\n',
        newline="\n",
    )

    def native_path(value):
        if os.name == "nt" and len(value) > 2 and value[0] == "/" and value[2] == "/":
            return Path(value[1] + ":" + value[2:])
        return Path(value)

    def invoke(tool="curl", *, codes="200 301 302 403 404 429 500", **kwargs):
        options = kwargs.pop("options", [])
        result = run(
            [
                "--url",
                "https://[::1]:65535/",
                "--tool",
                tool,
                "--candidates",
                str(len(codes.split())),
                "--evidence",
                bash_path(evidence),
                *options,
                "--execute",
            ],
            codes=codes,
            **kwargs,
        )
        return result, dict(line.split("=", 1) for line in evidence.read_text().splitlines())

    def argv():
        return args_file.read_bytes().decode().split("\0")[:-1]

    def alive():
        return (
            subprocess.run(
                [
                    bash,
                    "--noprofile",
                    "--norc",
                    "-c",
                    'kill -0 "$1" 2>/dev/null',
                    "check",
                    pid_file.read_text().strip(),
                ],
                capture_output=True,
                timeout=3,
                check=False,
            ).returncode
            == 0
        )

    yield invoke, argv, native_path, alive
    if pid_file.exists() and alive():
        subprocess.run(
            [
                bash,
                "--noprofile",
                "--norc",
                "-c",
                'kill -KILL "$1"; wait "$1" 2>/dev/null',
                "cleanup",
                pid_file.read_text().strip(),
            ],
            capture_output=True,
            timeout=3,
            check=False,
        )


def assert_web_distribution(summary, expected, *, planned, attempted, state="completed", code=0):
    """고정 집계 키를 모두 비교해 중복 집계와 부분 실패 후 증거 누락을 검출한다."""
    assert summary["state"] == state
    assert summary["exit_code"] == str(code)
    assert summary["planned_requests"] == str(planned)
    assert summary["attempted_requests"] == str(attempted)
    assert summary["observed_statuses"] == str(sum(expected))
    assert [int(summary[f"http_{status}"]) for status in (200, 301, 302, 403, 404, "other")] == (
        expected
    )


@pytest.mark.parametrize("tool", ["curl", "gobuster"])
def test_web_dry_run_without_installed_tool_creates_nothing(web_scan, tool):
    run, evidence, args_file, count_file, pid_file, bash_path = web_scan
    result = run(
        ["--url", "http://127.0.0.1", "--tool", tool, "--evidence", bash_path(evidence)],
        missing=tool,
    )
    assert result.returncode == 0 and "dry-run" in result.stdout
    assert all(not path.exists() for path in (evidence, args_file, count_file, pid_file))
    assert not list((args_file.parent / "web fake bin").glob("web-dir-scan-*.txt"))


@pytest.mark.parametrize("candidates,concurrency,timeout", [(1, 1, 1), (20, 4, 10)])
def test_web_gobuster_executes_boundaries_with_exact_wordlist(
    web_sequence, web_scan, candidates, concurrency, timeout
):
    invoke, argv, native_path, alive = web_sequence
    _, _, args_file, _, _, _ = web_scan
    result, summary = invoke(
        "gobuster",
        codes=" ".join(["200"] * candidates),
        options=["--concurrency", str(concurrency), "--timeout", str(timeout)],
    )
    assert result.returncode == 0, result.stderr
    assert_web_distribution(
        summary, [candidates, 0, 0, 0, 0, 0], planned=candidates, attempted="unknown"
    )
    arguments = argv()
    wordlist = arguments[arguments.index("-w") + 1]
    assert arguments == [
        "dir",
        "-q",
        "--no-color",
        "--no-progress",
        "--no-error",
        "-u",
        "https://[::1]:65535",
        "-w",
        wordlist,
        "-t",
        str(concurrency),
        "--timeout",
        f"{timeout}s",
        "-b",
        "",
        "-s",
        "200,301,302,403",
    ]
    words = args_file.with_name(args_file.name + ".words").read_text().splitlines()
    expected = [
        "admin",
        "login",
        "dashboard",
        "api",
        "health",
        "backup",
        "config",
        "robots.txt",
        "sitemap.xml",
        "uploads",
        "images",
        "static",
        "assets",
        "private",
        "internal",
        "debug",
        "status",
        "metrics",
        "old",
        "test",
    ]
    assert words == expected[:candidates]
    assert "; literal" in wordlist and not (native_path(wordlist).parent).exists()
    assert not alive()


@pytest.mark.parametrize("candidates,timeout", [(1, 1), (20, 10)])
def test_web_curl_exact_argv_and_boundary_attempt_counts(web_sequence, candidates, timeout):
    invoke, argv, _, _ = web_sequence
    result, summary = invoke(
        codes=" ".join(["404"] * candidates), options=["--timeout", str(timeout)]
    )
    assert result.returncode == 0, result.stderr
    assert_web_distribution(
        summary, [0, 0, 0, 0, candidates, 0], planned=candidates, attempted=candidates
    )
    arguments = argv()
    urls = [argument for argument in arguments if argument.startswith("https://")]
    assert len(urls) == candidates and len(set(urls)) == candidates
    for index, url in enumerate(urls):
        expected = [
            "-q",
            "--silent",
            "--noproxy",
            "*",
            "--proxy",
            "",
            "--max-redirs",
            "0",
            "--proto",
            "=http,https",
            "--connect-timeout",
            str(timeout),
            "--max-time",
            str(timeout),
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--",
            url,
        ]
        assert arguments[index * len(expected) : (index + 1) * len(expected)] == expected
    assert urls[0] == "https://[::1]:65535/admin"


def test_web_curl_mixed_repeated_statuses_and_no_redirect_requests(web_sequence, web_scan):
    invoke, argv, _, _ = web_sequence
    result, summary = invoke(codes="200 301 302 403 404 429 500 301 200 404")
    assert result.returncode == 0, result.stderr
    assert_web_distribution(summary, [2, 2, 1, 1, 2, 2], planned=10, attempted=10)
    urls = [argument for argument in argv() if argument.startswith("https://")]
    assert [url.rsplit("/", 1)[-1] for url in urls] == [
        "admin",
        "login",
        "dashboard",
        "api",
        "health",
        "backup",
        "config",
        "robots.txt",
        "sitemap.xml",
        "uploads",
    ]
    assert "--location" not in argv() and "-L" not in argv()
    assert web_scan[3].read_text().strip() == "10"


@pytest.mark.parametrize(
    "failure,state,code",
    [
        ("!6", "connection_failure", 6),
        ("!7", "connection_failure", 7),
        ("!28", "timeout", 124),
        ("!130", "interrupted", 130),
        ("!143", "interrupted", 143),
        ("!42", "tool_error", 42),
        ("000", "connection_failure", 7),
        ("MOCK-BODY", "tool_error", 70),
    ],
)
def test_web_curl_partial_failure_preserves_only_confirmed_responses(
    web_sequence, web_scan, failure, state, code
):
    invoke, argv, _, _ = web_sequence
    result, summary = invoke(codes=f"200 301 404 {failure} 403")
    assert result.returncode == code, result.stderr
    assert_web_distribution(
        summary, [1, 1, 0, 0, 1, 0], planned=5, attempted=4, state=state, code=code
    )
    assert web_scan[3].read_text().strip() == "4"
    assert len([arg for arg in argv() if arg.startswith("https://")]) == 4


@pytest.mark.parametrize(
    "failure,state,code",
    [
        ("!1", "connection_failure", 1),
        ("!28", "timeout", 124),
        ("!130", "interrupted", 130),
        ("!143", "interrupted", 143),
        ("!42", "tool_error", 42),
    ],
)
def test_web_gobuster_partial_failure_retains_filtered_observations(
    web_sequence, failure, state, code
):
    invoke, argv, native_path, alive = web_sequence
    result, summary = invoke("gobuster", codes=f"200 301 404 429 403 {failure} 302")
    assert result.returncode == code, result.stderr
    assert_web_distribution(
        summary, [1, 1, 0, 1, 0, 0], planned=7, attempted="unknown", state=state, code=code
    )
    assert not native_path(argv()[argv().index("-w") + 1]).parent.exists()
    assert not alive()


@pytest.mark.parametrize(
    "mode,state,code",
    [
        ("partial_int", "interrupted", 130),
        ("partial_interrupt", "interrupted", 143),
        ("partial_hang", "timeout", 124),
    ],
)
def test_web_gobuster_partial_signal_or_deadline_keeps_counts_and_cleans_files(
    web_sequence, mode, state, code
):
    invoke, argv, native_path, alive = web_sequence
    result, summary = invoke("gobuster", codes="200", mode=mode, options=["--timeout", "1"])
    assert result.returncode == code, result.stderr
    assert_web_distribution(
        summary, [1, 0, 0, 0, 0, 0], planned=1, attempted="unknown", state=state, code=code
    )
    directory = native_path(argv()[argv().index("-w") + 1]).parent
    assert not directory.exists()
    assert not alive()


@pytest.mark.parametrize("tool", ["curl", "gobuster"])
def test_web_evidence_is_only_summary_without_sensitive_raw_output(
    web_sequence, web_scan, monkeypatch, tool
):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "MOCK-AWS-SECRET")
    monkeypatch.setenv("HTTP_PROXY", "http://user:MOCK-PASSWORD@proxy.invalid")
    invoke, _, _, _ = web_sequence
    result, summary = invoke(tool, codes="200 301 302 403 404 429 500")
    assert result.returncode == 0, result.stderr
    assert_web_distribution(
        summary,
        [1, 1, 1, 1, 1 if tool == "curl" else 0, 2 if tool == "curl" else 0],
        planned=7,
        attempted=7 if tool == "curl" else "unknown",
    )
    assert set(summary) == {
        "started_at",
        "ended_at",
        "tool",
        "target",
        "state",
        "exit_code",
        "planned_requests",
        "attempted_requests",
        "observed_statuses",
        "http_200",
        "http_301",
        "http_302",
        "http_403",
        "http_404",
        "http_other",
    }
    assert summary["tool"] == tool and summary["target"] == "https://[::1]:65535"
    assert summary["started_at"] <= summary["ended_at"]
    for timestamp in (summary["started_at"], summary["ended_at"]):
        assert len(timestamp) == 20 and timestamp.endswith("Z")
    output = web_scan[1].read_text() + result.stdout + result.stderr
    for secret in ("MOCK-AWS-SECRET", "MOCK-PASSWORD", "MOCK-TOKEN", "MOCK-BODY", "[Size:"):
        assert secret not in output


def test_web_evidence_metacharacters_are_literal_and_second_run_cannot_append(web_scan):
    run, _, args_file, count_file, _, bash_path = web_scan
    evidence = args_file.parent / "summary ; $(touch INJECTED).txt"
    options = [
        "--url",
        "http://127.0.0.1",
        "--candidates",
        "1",
        "--evidence",
        bash_path(evidence),
        "--execute",
    ]
    result = run(options)
    assert result.returncode == 0, result.stderr
    original = evidence.read_bytes()
    original_args = args_file.read_bytes()
    result = run(options)
    assert result.returncode == 2, result.stderr
    assert evidence.read_bytes() == original and args_file.read_bytes() == original_args
    assert count_file.read_text().strip() == "1"
    assert not (args_file.parent / "web fake bin" / "INJECTED").exists()


@pytest.mark.parametrize("tool", ["curl", "gobuster"])
def test_web_missing_tool_summary_has_zero_attempts_and_observations(web_sequence, web_scan, tool):
    result, summary = web_sequence[0](tool, codes="200 301 302 403 404", missing=tool)
    assert result.returncode == 127, result.stderr
    assert_web_distribution(
        summary, [0, 0, 0, 0, 0, 0], planned=5, attempted=0, state="tool_missing", code=127
    )
    assert all(not path.exists() for path in web_scan[2:5])


@pytest.mark.parametrize(
    "option,value",
    [
        ("--candidates", "999999999999999999999999"),
        ("--concurrency", "5"),
        ("--timeout", "11"),
    ],
)
def test_web_gobuster_over_limit_creates_no_evidence_or_temp(web_sequence, web_scan, option, value):
    run, evidence, args_file, count_file, pid_file, bash_path = web_scan
    result = run(
        [
            "--url",
            "http://127.0.0.1",
            "--tool",
            "gobuster",
            "--evidence",
            bash_path(evidence),
            option,
            value,
            "--execute",
        ]
    )
    assert result.returncode == 2, result.stderr
    assert all(not path.exists() for path in (evidence, args_file, count_file, pid_file))
    assert not args_file.with_name(args_file.name + ".temp").exists()


def test_web_curl_rejects_parallelism_before_creating_evidence(web_scan):
    run, evidence, args_file, count_file, pid_file, bash_path = web_scan
    result = run(
        [
            "--url",
            "http://127.0.0.1",
            "--concurrency",
            "2",
            "--evidence",
            bash_path(evidence),
            "--execute",
        ]
    )
    assert result.returncode == 2, result.stderr
    assert all(not path.exists() for path in (evidence, args_file, count_file, pid_file))


def test_web_cleanup_keeps_unrelated_process_and_file(web_sequence, web_scan, bash):
    """동일 환경의 비소유 PID·파일을 보존하고 테스트가 만든 대조 PID는 finally에서 회수한다."""
    unrelated = web_scan[2].parent / "unrelated.txt"
    unrelated.write_text("keep original")
    other = subprocess.Popen(
        [bash, "--noprofile", "--norc", "-c", "printf '%s\\n' $$; exec /usr/bin/sleep 30"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        other_pid = other.stdout.readline().strip()
        result, summary = web_sequence[0]("gobuster", codes="200", mode="partial_interrupt")
        assert result.returncode == 143 and summary["state"] == "interrupted"
        assert other.poll() is None
        assert unrelated.read_text() == "keep original"
        assert not web_sequence[3]()
    finally:
        subprocess.run(
            [bash, "--noprofile", "--norc", "-c", 'kill -TERM "$1"', "cleanup", other_pid],
            capture_output=True,
            timeout=3,
            check=False,
        )
        other.wait(timeout=3)
        other.stdout.close()


def spray_spec(**overrides):
    return dict(
        hydra_spec(),
        **dict(
            candidates=1,
            seconds=30,
            accounts=["spraylab3", "spraylab1", "spraylab2"],
            interval=2,
            max_attempts=3,
        )
        | overrides,
    )


@pytest.mark.parametrize("options", [[], ["run"], ["plan", "--execute"]])
def test_spray_dry_run_never_calls_docker(hydra_lab, monkeypatch, options, capsys):
    host, _, _ = hydra_lab
    monkeypatch.setattr(host.HydraLab, "preflight", lambda *_: pytest.fail("Docker called"))
    assert host.main([*options, "--mode", "password-spraying"]) == 0
    assert "Password Spraying" in capsys.readouterr().out


@pytest.mark.parametrize(
    "options",
    [
        ["--accounts", "root", "admin"],
        ["--accounts", "spraylab1"],
        ["--accounts", "spraylab1", "spraylab1"],
        ["--accounts", "spraylab1", "spraylab11"],
        ["--accounts", "spraylab1", "spraylab2;id"],
        ["--accounts"],
        ["--interval", "0"],
        ["--interval", "11"],
        ["--interval", "nan"],
        ["--max-attempts", "1"],
        ["--max-attempts", "11"],
        ["--accounts", "spraylab1", "spraylab2", "spraylab3", "--max-attempts", "2"],
        ["--seconds", "3", "--interval", "3"],
        ["--seconds", "56"],
        ["--target", "10.0.0.1"],
        ["--target", "127.0.0.1"],
        ["--port", "22"],
        ["--tasks", "2"],
        ["--candidates", "1"],
        ["--password", "MOCK-SECRET"],
    ],
)
def test_spray_cli_rejects_invalid_inputs_before_side_effects(hydra_lab, monkeypatch, options):
    host, _, _ = hydra_lab
    monkeypatch.setattr(host.HydraLab, "__init__", lambda *a, **k: pytest.fail("Lab created"))
    with pytest.raises(SystemExit) as exc:
        host.main(["run", "--execute", "--mode", "password-spraying", *options])
    assert exc.value.code == 2


@pytest.mark.parametrize(
    "override",
    [
        {"accounts": []},
        {"accounts": "spraylab1"},
        {"accounts": [None, "spraylab1"]},
        {"accounts": ["spraylab1", "spraylab1"]},
        {"interval": True},
        {"interval": 1.5},
        {"max_attempts": 2},
        {"max_attempts": 11},
        {"candidates": 2},
        {"target": "127.0.0.1;id"},
    ],
)
def test_spray_worker_revalidates_stdin(hydra_lab, monkeypatch, override):
    worker = hydra_lab[1]
    monkeypatch.setattr(worker.shutil, "which", lambda *_: pytest.fail("External lookup"))
    with pytest.raises(ValueError):
        worker.execute(spray_spec(**override))


@pytest.fixture
def spray_process(hydra_lab, monkeypatch, tmp_path):
    """실제 Hydra 폴백 없이 argv·private 후보를 관측하고 가상 시계로 순서와 중단을 검증한다."""
    worker = hydra_lab[1]
    original_temp = tempfile.TemporaryDirectory
    monkeypatch.setattr(
        worker.tempfile,
        "TemporaryDirectory",
        lambda **kw: original_temp(prefix="spray-", dir=tmp_path),
    )
    monkeypatch.setattr(worker.os, "umask", lambda *_: None)
    monkeypatch.setattr(worker.shutil, "which", lambda *_: "mock-hydra")
    monkeypatch.setattr(
        worker.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a, 0, "Hydra MOCK\n-K\nSupported services: ssh\n", ""
        ),
    )
    evidence = dict(calls=[], sleeps=[], now=0, mode="normal", secrets=[], folders=[])
    monkeypatch.setattr(worker.time, "monotonic", lambda: evidence["now"])

    def sleep(seconds):
        evidence["sleeps"].append(seconds)
        evidence["now"] += seconds

    monkeypatch.setattr(worker.time, "sleep", sleep)

    class FakeHydra:
        pid = 7123
        returncode = 0

        def __init__(self, argv, cwd, stdout, **kwargs):
            evidence["calls"].append((argv, evidence["now"]))
            evidence["folders"].append(cwd)
            secret = (cwd / "candidates").read_text()
            evidence["secrets"].append(secret)
            (cwd / "hydra.restore").write_text(secret)
            assert kwargs["start_new_session"] is True
            mode = evidence["mode"] if len(evidence["calls"]) == 2 else "normal"
            if mode == "launch_error":
                raise OSError("MOCK-SECRET launch error")
            if mode == "deadline":
                evidence["now"] = 30
            if mode == "interrupt":
                raise KeyboardInterrupt()
            if mode == "failure":
                self.returncode = 1
            stdout.write(
                {
                    "success": "[2222][ssh] login: spraylab1 password: " + secret,
                    "failure": "[ERROR] could not connect " + secret,
                    "unconfirmed": "",
                }.get(mode, "0 valid passwords found")
            )
            stdout.flush()

        def poll(self):
            return self.returncode

    monkeypatch.setattr(worker.subprocess, "Popen", FakeHydra)
    return worker, evidence


def test_spray_order_shared_secret_gap_and_cleanup(spray_process):
    worker, evidence = spray_process
    result = worker.execute(spray_spec())
    assert result["state"] == "exhausted_without_success"
    assert result["attempted_accounts"] == 3
    assert evidence["sleeps"] == [2, 2]
    assert len(set(evidence["secrets"])) == 1
    for (argv, when), account, expected_time in zip(
        evidence["calls"], spray_spec()["accounts"], [0, 2, 4], strict=True
    ):
        candidate_path = argv[argv.index("-P") + 1]
        assert argv == [
            "mock-hydra",
            "-I",
            "-K",
            "-f",
            "-l",
            account,
            "-P",
            candidate_path,
            "-t",
            "1",
            "-w",
            "3",
            "-s",
            "2222",
            "192.0.2.2",
            "ssh",
        ]
        assert when == expected_time
        assert evidence["secrets"][0].strip() not in json.dumps(argv) + json.dumps(result)
    assert all(not folder.exists() for folder in evidence["folders"])


@pytest.mark.parametrize(
    "mode,state",
    [
        ("failure", "connection_error"),
        ("success", "unexpected_success"),
        ("unconfirmed", "unconfirmed"),
        ("deadline", "timeout"),
        ("launch_error", None),
        ("interrupt", None),
    ],
)
def test_spray_stops_after_partial_failure(spray_process, mode, state):
    worker, evidence = spray_process
    evidence["mode"] = mode
    if state is None:
        with pytest.raises((OSError, KeyboardInterrupt)):
            worker.execute(spray_spec())
    else:
        result = worker.execute(spray_spec())
        assert result["state"] == state
        assert result["attempted_accounts"] == 2
        for secret in evidence["secrets"]:
            assert secret.strip() not in json.dumps(result)
    assert len(evidence["calls"]) == 2
    assert all(not folder.exists() for folder in evidence["folders"])


def test_spray_maximum_account_limit_has_no_extra_round(spray_process):
    worker, evidence = spray_process
    result = worker.execute(
        spray_spec(
            accounts=[f"spraylab{i}" for i in range(1, 11)], interval=1, max_attempts=10, seconds=55
        )
    )
    assert result["attempted_accounts"] == 10
    assert len(evidence["calls"]) == 10 and len(evidence["sleeps"]) == 9


@pytest.mark.parametrize("complete", [True, False])
def test_spray_server_evidence_requires_each_requested_account(
    hydra_lab, monkeypatch, tmp_path, complete
):
    host, _, _ = hydra_lab
    lab = host.HydraLab(tmp_path / "spray", 1, accounts=["spraylab2", "spraylab1"])
    accounts = ["spraylab2", "spraylab1"] if complete else ["spraylab2", "spraylab2"]
    log = "".join(
        f"Failed password for invalid user {a} from 192.0.2.3 port 4000 ssh2\n" for a in accounts
    )
    log += "Failed password for invalid user spraylab1 from 192.0.2.4 port 4000 ssh2\n"
    monkeypatch.setattr(lab, "call", lambda *a, **k: subprocess.CompletedProcess(a, 0, "", log))
    if complete:
        assert lab.server_evidence("server", "192.0.2.3") == (2, 0)
    else:
        with pytest.raises(RuntimeError, match="계정별"):
            lab.server_evidence("server", "192.0.2.3")
    assert (lab.output / "sshd.log").read_text() == log


def test_spray_shell_syntax(bash):
    script = Path(__file__).resolve().parents[2] / "network/password_spraying.sh"
    result = subprocess.run([bash, "-n", script.as_posix()], capture_output=True, check=False)
    assert result.returncode == 0
