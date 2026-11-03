"""소유 컨테이너의 유한 HTTP 전송과 수신측 IFB 주입을 분리한다.

Why: 재연결을 숨기지 않고 패킷 도착 순서와 앱 본문 무결성을 독립 관측한다.
Constraints: IPv4 8080, 연결/GET 1회, 본문 64KiB, 캡처 20초/1024패킷.
Side-effects: 명시적 CLI에서만 소켓·qdisc·소유 캡처를 만들며 부분 증거와 오류를 남긴다.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path

from packet_worker import FILE_BYTES, LOG_BYTES, PORT, file_limit, save, stamp, stop

PROFILE = "cloudshield-netem-v1"
SCENARIOS = ("baseline", "delay", "loss", "reorder")
DIRECTORY = Path("/run/evidence")
BODY = b"".join(
    hashlib.sha256(f"cloudshield-netem-v1:{i:04d}".encode()).digest() for i in range(2048)
)
BODY_SHA256 = "37b857dfabe9385104eebfab545643c6a1e06e42657d5de6c7e24229c4fab340"
CAPTURE_SECONDS = 20
PACKETS = 1024


def worker_identity():
    return {
        "worker_pid": os.getpid(),
        "worker_start": Path("/proc/self/stat").read_text().split()[21],
    }


def validate(scenario, run_id, server=None, client=None):
    if scenario not in SCENARIOS or not re.fullmatch(r"cs-netem-[a-f0-9]{32}", run_id):
        raise ValueError("전용 시나리오/실행 ID 오류")
    if server is not None:
        values = [ipaddress.IPv4Address(v) for v in (server, client)]
        if values[0] == values[1] or any(
            not v.is_private or v.is_loopback or v.is_multicast or v.is_unspecified for v in values
        ):
            raise ValueError("소유 internal bridge의 서로 다른 IPv4 필요")


def request(run_id):
    return (
        "GET /payload HTTP/1.1\r\nHost: local.test\r\n"
        f"X-Run-ID: {run_id}\r\nConnection: close\r\n\r\n"
    ).encode()


def response_head(run_id):
    return (
        f"HTTP/1.1 200 OK\r\nX-Run-ID: {run_id}\r\n"
        "Content-Length: 65536\r\nConnection: close\r\n\r\n"
    ).encode()


def netem_options(scenario, seed_supported=False):
    if scenario not in SCENARIOS or type(seed_supported) is not bool:
        raise ValueError("주입 설정 오류")
    options = ["netem", "limit", "128"]
    if scenario == "delay":
        options += ["delay", "50ms"]
    elif scenario == "loss":
        options += ["loss", "random", "10%"]
        if seed_supported:
            options += ["seed", "20261102"]
    elif scenario == "reorder":
        options += ["delay", "50ms", "reorder", "100%", "gap", "3"]
    return options


def command(events, *args, check=True):
    result = subprocess.run(args, capture_output=True, timeout=2)
    if len(result.stdout) > LOG_BYTES or len(result.stderr) > LOG_BYTES:
        raise ValueError("설정 도구 로그 상한 초과")
    value = {
        "args": list(args),
        "code": result.returncode,
        "stdout": result.stdout.decode("utf-8", errors="replace"),
        "stderr": result.stderr.decode("utf-8", errors="replace"),
        "epoch": stamp(),
    }
    events.append(value)
    if len(json.dumps(events).encode()) > FILE_BYTES:
        raise ValueError("설정 명령 기록 상한 초과")
    if check and result.returncode:
        raise RuntimeError("설정 도구 실패: " + " ".join(args) + ": " + value["stderr"])
    return value


def qdisc(events):
    return json.loads(command(events, "tc", "-s", "-j", "qdisc", "show", "dev", "ifb0")["stdout"])


def verify_qdisc(scenario, snapshot):
    if not isinstance(snapshot, list) or len(snapshot) != 1 or snapshot[0].get("kind") != "netem":
        raise ValueError("실제 qdisc 종류/개수 불일치")
    options = snapshot[0].get("options", {})
    actual = (
        options.get("limit"),
        options.get("delay", {}).get("delay", 0),
        options.get("loss-random", {}).get("loss", 0),
        options.get("reorder", {}).get("reorder", 0),
        options.get("gap", 0),
    )
    expected = {
        "baseline": (128, 0, 0, 0, 0),
        "delay": (128, 0.05, 0, 0, 0),
        "loss": (128, 0, 0.1, 0, 0),
        "reorder": (128, 0.05, 0, 1, 3),
    }
    if scenario not in expected or actual != expected[scenario]:
        raise ValueError("실제 장애 조건 불일치/설정 혼합")
    for key in ("packets", "bytes", "drops", "backlog", "qlen"):
        if type(snapshot[0].get(key)) is not int or snapshot[0][key] < 0:
            raise ValueError("qdisc 카운터 형식/범위")


def prepare(scenario, run_id, server, client, seed_supported):
    validate(scenario, run_id, server, client)
    if type(seed_supported) is not bool:
        raise ValueError("seed 지원 표기 형식")
    control = DIRECTORY / "control"
    control.mkdir(exist_ok=False)
    events = []
    for module in ("ifb", "sch_netem", "sch_ingress", "cls_u32", "act_mirred"):
        if not Path("/sys/module", module).is_dir():
            raise RuntimeError("environment_not_ready: " + module)
    command(events, "ip", "link", "add", "ifb0", "type", "ifb")
    command(events, "ip", "link", "set", "ifb0", "up")
    command(events, "tc", "qdisc", "add", "dev", "ifb0", "root", *netem_options("baseline"))
    command(events, "tc", "qdisc", "add", "dev", "eth0", "clsact")
    command(
        events,
        "tc",
        "filter",
        "add",
        "dev",
        "eth0",
        "ingress",
        "protocol",
        "ip",
        "prio",
        "1",
        "u32",
        "match",
        "ip",
        "src",
        server + "/32",
        "match",
        "ip",
        "dst",
        client + "/32",
        "match",
        "ip",
        "protocol",
        "6",
        "0xff",
        "match",
        "ip",
        "sport",
        str(PORT),
        "0xffff",
        "action",
        "mirred",
        "egress",
        "redirect",
        "dev",
        "ifb0",
    )
    # 송신측 권한 추가 없이 수신측만 조정하며, 미지원 항목도 실제 설정과 함께 보존한다.
    for device in ("eth0", "ifb0"):
        command(events, "ethtool", "-k", device, check=False)
        for feature in ("gro", "gso", "tso"):
            command(events, "ethtool", "-K", device, feature, "off", check=False)
        command(events, "ethtool", "-k", device, check=False)
    value = {
        "profile": PROFILE,
        "scenario": scenario,
        "run_id": run_id,
        "server": server,
        "client": client,
        "seed_supported": seed_supported,
        "commands": events,
    }
    save(control / "prepare.json", value)
    return value


def arm(scenario, run_id):
    validate(scenario, run_id)
    prepared = json.loads((DIRECTORY / "control/prepare.json").read_bytes())
    config = json.loads((DIRECTORY / "config.json").read_bytes())
    if any(prepared[k] != config[k] for k in ("profile", "scenario", "run_id", "server", "client")):
        raise ValueError("다른 실행의 주입 설정")
    if config["run_id"] != run_id or config["scenario"] != scenario:
        raise ValueError("다른 실행의 arm 요청")
    events = []
    before = qdisc(events)
    applied = stamp()
    command(
        events,
        "tc",
        "qdisc",
        "change",
        "dev",
        "ifb0",
        "root",
        *netem_options(scenario, prepared["seed_supported"]),
    )
    after = qdisc(events)
    verify_qdisc(scenario, after)
    value = {
        **prepared,
        "applied_epoch": applied,
        "verified_epoch": stamp(),
        "before": before,
        "after": after,
        "arm_commands": events,
        "seed": 20261102 if scenario == "loss" and prepared["seed_supported"] else None,
    }
    save(DIRECTORY / "injection.json", value)
    save(DIRECTORY / "control/armed.json", {"run_id": run_id})
    return value


def feature_probe(run_id, server, client):
    prepared = prepare("baseline", run_id, server, client, False)
    save(
        DIRECTORY / "config.json",
        {
            "run_id": run_id,
            "role": "client",
            **worker_identity(),
        },
    )
    events, supported = [], False
    result = {
        "profile": PROFILE,
        "run_id": run_id,
        "complete": False,
        "tcp_connections": 0,
        "http_requests": 0,
        "prepared": prepared,
        "commands": events,
    }
    try:
        attempt = command(
            events,
            "tc",
            "qdisc",
            "change",
            "dev",
            "ifb0",
            "root",
            *netem_options("loss", True),
            check=False,
        )
        supported = attempt["code"] == 0
        if not supported and 'What is "seed"?' not in attempt["stderr"]:
            raise RuntimeError("seed 확인 중 예상 밖 설정 오류")
        for scenario in SCENARIOS:
            command(
                events,
                "tc",
                "qdisc",
                "change",
                "dev",
                "ifb0",
                "root",
                *netem_options(scenario, supported),
            )
            snapshot = qdisc(events)
            verify_qdisc(scenario, snapshot)
            if any(snapshot[0][key] for key in ("packets", "bytes", "drops", "backlog", "qlen")):
                raise ValueError("무트래픽 기능 시험에 예기치 않은 패킷")
        result.update(complete=True, seed_supported=supported)
    finally:
        try:
            command(events, "tc", "qdisc", "del", "dev", "eth0", "clsact")
            command(events, "tc", "qdisc", "del", "dev", "ifb0", "root")
            command(events, "ip", "link", "del", "ifb0")
            result["removed"] = True
        except Exception as exc:
            result.update(complete=False, removed=False, cleanup_error=type(exc).__name__)
        save(DIRECTORY / "feature.json", result)
    return 0 if result["complete"] else 1


class Journal:
    def __init__(self, scenario, run_id, role):
        self.value = {
            "profile": PROFILE,
            "scenario": scenario,
            "run_id": run_id,
            "role": role,
            "events": [],
        }

    def event(self, kind, **fields):
        item = {
            "event_id": len(self.value["events"]) + 1,
            "event": kind,
            "epoch": stamp(),
            "monotonic_ns": time.monotonic_ns(),
            **fields,
        }
        if (
            len(self.value["events"]) >= 256
            or len(json.dumps(self.value).encode()) + len(json.dumps(item).encode()) > LOG_BYTES
        ):
            raise ValueError("앱 로그 개수/64KiB 상한")
        self.value["events"].append(item)
        return item

    def opened(self, sock):
        self.value["socket"] = {
            "id": f"{self.value['run_id']}:{self.value['role']}:1",
            "pid": os.getpid(),
            "fd": sock.fileno(),
            "local": list(sock.getsockname()),
            "remote": list(sock.getpeername()),
            "mss": sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG),
        }
        self.event("socket_open")


class Capture:
    """PCAP 1MiB와 파이프 로그 64KiB를 분리해 큰 본문을 로그 제한으로 자르지 않는다."""

    def __init__(self, prefix, device, peer):
        self.prefix, self.buffers, self.errors = prefix, {}, []
        self.device, self.peer = device, peer
        self.started, self.started_epoch = time.monotonic(), stamp()
        self.process = subprocess.Popen(
            [
                "bash",
                "/opt/network/tcpdump_capture.sh",
                peer,
                str(PORT),
                device,
                str(DIRECTORY / (prefix + ".pcap")),
                str(CAPTURE_SECONDS),
                str(PACKETS),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=file_limit,
        )
        self.threads = []
        for name, pipe in (("stdout", self.process.stdout), ("stderr", self.process.stderr)):
            self.buffers[name] = bytearray()
            thread = threading.Thread(target=self.drain, args=(name, pipe), daemon=True)
            thread.start()
            self.threads.append(thread)

    def drain(self, name, pipe):
        try:
            with (DIRECTORY / (self.prefix + "." + name)).open("xb") as output:
                while True:
                    data = os.read(pipe.fileno(), 4096)
                    if not data:
                        break
                    left = LOG_BYTES - len(self.buffers[name])
                    output.write(data[:left])
                    self.buffers[name].extend(data[:left])
                    if len(data) > left and "log_limit" not in self.errors:
                        self.errors.append("log_limit")
                output.flush()
                os.fsync(output.fileno())
        except Exception as exc:
            self.errors.append(type(exc).__name__)
        finally:
            pipe.close()

    def ready(self):
        if self.errors or self.process.poll() is not None:
            raise RuntimeError("캡처 준비 실패/조기 종료")
        return b"listening on " in self.buffers["stderr"]

    def finish(self, normal=True):
        if normal:
            self.process.wait(timeout=max(0.001, self.started + 23 - time.monotonic()))
        stop(self.process)
        for thread in self.threads:
            thread.join(timeout=1)
        raw = bytes(self.buffers["stderr"]).decode("utf-8", errors="replace")
        captured = re.search(r"(?m)^(\d+) packets captured$", raw)
        dropped = re.search(r"(?m)^(\d+) packets dropped by kernel$", raw)
        path = DIRECTORY / (self.prefix + ".pcap")
        value = {
            "interface": self.device,
            "peer": self.peer,
            "started_epoch": self.started_epoch,
            "ended_epoch": stamp(),
            "exit": self.process.returncode,
            "errors": self.errors,
            "packets": int(captured[1]) if captured else None,
            "kernel_dropped": int(dropped[1]) if dropped else None,
            "bytes": path.stat().st_size if path.exists() else 0,
        }
        value["valid"] = bool(
            normal
            and not self.errors
            and not any(t.is_alive() for t in self.threads)
            and value["exit"] == 124
            and "시간 제한 도달" in raw
            and "SIGKILL" not in raw
            and captured
            and dropped
            and 0 < int(captured[1]) < PACKETS
            and int(dropped[1]) == 0
            and 24 < value["bytes"] <= FILE_BYTES
        )
        return value


def ready(captures):
    deadline = time.monotonic() + 3
    while not all(c.ready() for c in captures):
        if time.monotonic() >= deadline:
            raise TimeoutError("공통 캡처 준비 3초 상한")
        time.sleep(0.01)


def io_timeout(sock, deadline, connect=False):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("앱 전체 시간 상한")
    sock.settimeout(min(3 if connect else 5, left))


def configure(sock):
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1200)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


def receive_request(sock, deadline):
    raw = b""
    while b"\r\n\r\n" not in raw:
        io_timeout(sock, deadline)
        part = sock.recv(2049 - len(raw))
        if not part:
            raise EOFError("요청 완료 전 EOF")
        raw += part
        if len(raw) > 2048:
            raise ValueError("합성 요청 상한")
    return raw


def extend_body(body, part):
    remaining = len(BODY) - len(body)
    body.extend(part[:remaining])
    if len(part) > remaining:
        raise ValueError("본문 64KiB 초과")


def client_exchange(scenario, run_id, server, client, journal):
    deadline, body = time.monotonic() + 15, bytearray()
    metrics = {"connect_seconds": None, "first_byte_seconds": None, "complete_seconds": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            configure(sock)
            sock.bind((client, 0))
            io_timeout(sock, deadline, connect=True)
            started = journal.event("connect_started")["monotonic_ns"]
            sock.connect((server, PORT))
            returned = journal.event("connect_returned")["monotonic_ns"]
            metrics["connect_seconds"] = (returned - started) / 1e9
            journal.opened(sock)
            save(DIRECTORY / "control/connected.json", {"run_id": run_id})
            barrier = time.monotonic() + 3
            while not (DIRECTORY / "control/armed.json").exists():
                if time.monotonic() >= min(barrier, deadline):
                    raise TimeoutError("handshake 이후 주입 barrier 상한")
                time.sleep(0.01)
            if json.loads((DIRECTORY / "control/armed.json").read_bytes())["run_id"] != run_id:
                raise ValueError("다른 실행의 barrier")
            sent = journal.event("request_send_started")["monotonic_ns"]
            io_timeout(sock, deadline)
            sock.sendall(request(run_id))
            journal.event("request_send_returned", bytes=len(request(run_id)))
            header, first = bytearray(), True
            while len(body) < len(BODY):
                io_timeout(sock, deadline)
                data = sock.recv(4096)
                if not data:
                    raise EOFError("본문 완료 전 EOF")
                event = journal.event("receive", bytes=len(data))
                if first:
                    metrics["first_byte_seconds"] = (event["monotonic_ns"] - sent) / 1e9
                    first = False
                if header is not None:
                    header.extend(data)
                    marker = header.find(b"\r\n\r\n")
                    if marker < 0:
                        if len(header) > 2048:
                            raise ValueError("응답 헤더 상한")
                        continue
                    if bytes(header[: marker + 4]) != response_head(run_id):
                        raise ValueError("응답 상태/Content-Length/실행 ID 불일치")
                    journal.value["http"] = {
                        "status": 200,
                        "content_length": 65536,
                        "header_bytes": marker + 4,
                    }
                    extend_body(body, header[marker + 4 :])
                    header = None
                else:
                    extend_body(body, data)
                if len(body) > len(BODY):
                    raise ValueError("본문 64KiB 초과")
            if hashlib.sha256(body).hexdigest() != BODY_SHA256:
                raise ValueError("앱 본문 무결성 불일치")
            completed = journal.event(
                "body_complete", bytes=len(body), sha256=hashlib.sha256(body).hexdigest()
            )
            metrics["complete_seconds"] = (completed["monotonic_ns"] - sent) / 1e9
            sock.shutdown(socket.SHUT_WR)
            io_timeout(sock, deadline)
            if sock.recv(1) != b"":
                raise ValueError("계획 밖 응답 데이터")
            journal.event("eof")
    finally:
        with (DIRECTORY / "body.bin").open("xb") as output:
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        journal.value["metrics"] = metrics
        journal.value["body"] = {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def server_exchange(scenario, run_id, server, client, journal):
    deadline = time.monotonic() + 18
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        configure(listener)
        listener.bind((server, PORT))
        listener.listen(1)
        io_timeout(listener, deadline)
        sock, peer = listener.accept()
        listener.close()
        with sock:
            if peer[0] != client:
                raise ValueError("소유 클라이언트 이외 연결")
            journal.opened(sock)
            save(DIRECTORY / "control/accepted.json", {"run_id": run_id})
            raw = receive_request(sock, deadline)
            if raw != request(run_id):
                raise ValueError("합성 GET 1회/실행 ID 불일치")
            journal.event(
                "request_received", bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()
            )
            io_timeout(sock, deadline)
            sock.sendall(response_head(run_id))
            journal.value["http"] = {
                "status": 200,
                "content_length": 65536,
                "header_bytes": len(response_head(run_id)),
            }
            journal.event("response_head_sent", bytes=len(response_head(run_id)))
            for offset in range(0, len(BODY), 1024):
                io_timeout(sock, deadline)
                sock.sendall(BODY[offset : offset + 1024])
                journal.event("body_send_returned", offset=offset, bytes=1024)
                time.sleep(0.001)
            sock.shutdown(socket.SHUT_WR)
            io_timeout(sock, deadline)
            if sock.recv(1) != b"":
                raise ValueError("GET 뒤 계획 밖 데이터/추가 요청")
            journal.event("eof")


def run(role, scenario, run_id, server, client):
    validate(scenario, run_id, server, client)
    if role not in ("server", "client"):
        raise ValueError("worker 역할 오류")
    config = {
        "profile": PROFILE,
        "scenario": scenario,
        "run_id": run_id,
        "role": role,
        "server": server,
        "client": client,
        "connections": 1,
        "requests": 1,
        "body_bytes": len(BODY),
        "body_sha256": BODY_SHA256,
        "capture_seconds": 20,
        "packets": PACKETS,
        "file_bytes": FILE_BYTES,
        **worker_identity(),
    }
    save(DIRECTORY / ("s-config.json" if role == "server" else "config.json"), config)
    journal = Journal(scenario, run_id, role)
    result = {
        **config,
        "worker_complete": False,
        "transfer_complete": False,
        "captures": {},
        "errors": [],
    }
    captures = []
    try:
        if role == "server":
            (DIRECTORY / "control").mkdir(exist_ok=False)
        capture_plan = (
            [("s", "eth0", client)]
            if role == "server"
            else [("p", "eth0", server), ("q", "ifb0", server)]
        )
        for prefix, device, peer in capture_plan:
            captures.append(Capture(prefix, device, peer))
        ready(captures)
        try:
            (server_exchange if role == "server" else client_exchange)(
                scenario, run_id, server, client, journal
            )
            result["transfer_complete"] = True
        except (OSError, EOFError, TimeoutError, ValueError) as exc:
            result["errors"].append(
                {"stage": "transfer", "error": type(exc).__name__, "detail": str(exc)}
            )
        for capture in captures:
            result["captures"][capture.prefix] = capture.finish()
        result["worker_complete"] = all(v["valid"] for v in result["captures"].values())
    except (Exception, KeyboardInterrupt) as exc:
        result["errors"].append(
            {"stage": "worker", "error": type(exc).__name__, "detail": str(exc)}
        )
    finally:
        for capture in captures:
            if capture.prefix not in result["captures"]:
                try:
                    result["captures"][capture.prefix] = capture.finish(normal=False)
                except (Exception, KeyboardInterrupt) as exc:
                    result["errors"].append(
                        {"stage": "capture_cleanup", "error": type(exc).__name__}
                    )
        if role == "client":
            events = []
            try:
                final = {"before_removal": qdisc(events), "removal_epoch": stamp()}
                command(events, "tc", "qdisc", "del", "dev", "eth0", "clsact")
                command(events, "tc", "qdisc", "del", "dev", "ifb0", "root")
                command(events, "ip", "link", "del", "ifb0")
                final.update(commands=events, removed=True)
            except Exception as exc:
                final = {"commands": events, "removed": False, "error": type(exc).__name__}
                result["worker_complete"] = False
            save(DIRECTORY / "final.json", final)
        save(DIRECTORY / ("s-app.json" if role == "server" else "c-app.json"), journal.value)
        save(DIRECTORY / ("s-result.json" if role == "server" else "c-result.json"), result)
    return 0 if result["worker_complete"] else 1


def quiescent(run_id, role, wait=False):
    config = json.loads(
        (DIRECTORY / ("s-config.json" if role == "server" else "config.json")).read_bytes()
    )
    if config["run_id"] != run_id or config["role"] != role:
        raise ValueError("다른 실행/역할의 worker")
    deadline = time.monotonic() + (24 if wait else 0)
    while True:
        try:
            fields = Path(f"/proc/{config['worker_pid']}/stat").read_text().split()
        except FileNotFoundError:
            return 0
        if fields[21] != config["worker_start"] or fields[2] == "Z":
            return 0
        if time.monotonic() >= deadline:
            return 1
        time.sleep(0.05)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("prepare", "arm", "server", "client", "quiescent", "wait", "probe")
    )
    parser.add_argument("scenario")
    parser.add_argument("run_id")
    parser.add_argument("server", nargs="?")
    parser.add_argument("client", nargs="?")
    parser.add_argument("--seed-supported", action="store_true")
    args = parser.parse_args(argv)

    def interrupt(_signal, _frame):
        raise KeyboardInterrupt("상위 프로세스/사용자 중단")

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    if args.action in ("quiescent", "wait"):
        return quiescent(args.run_id, args.scenario, args.action == "wait")
    if args.action == "prepare":
        prepare(args.scenario, args.run_id, args.server, args.client, args.seed_supported)
        return 0
    if args.action == "arm":
        arm(args.scenario, args.run_id)
        return 0
    if args.action == "probe":
        return feature_probe(args.run_id, args.server, args.client)
    return run(args.action, args.scenario, args.run_id, args.server, args.client)


if __name__ == "__main__":
    raise SystemExit(main())
