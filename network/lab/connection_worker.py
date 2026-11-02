"""유한 합성 소켓으로 HTTP 거부와 TCP 수명주기를 구분한다. import는 부작용이 없다.

Why: 자동 재연결을 숨기는 HTTP 클라이언트를 배제하고 양쪽 앱 수신을 직접 기록한다.
Constraints: IPv4 TCP 8080, HTTP 3회/최대 2연결, TCP 메시지별 256B, 클라이언트 10초.
Side-effects: 명시적 serve/trial에서만 소유 소켓·캡처를 만들고 실패·부분 증거를 전파한다.
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from packet_worker import FILE_BYTES, LOG_BYTES, PORT, file_limit, save, stamp, stop

SCENARIOS = ("http_reuse", "http_close", "half_close", "established_rst")
DIRECTORY = Path("/run/evidence")
CAPTURE_SECONDS = 15
PACKETS = 512
HALF_REQUEST = b"half-close-request\n"
HALF_RESPONSE = b"half-close-response\n"
RESET_REQUEST = b"established-reset-request\n"
PROFILE = "cloudshield-connection-v1"


def validate(scenario, run_id, target=None, client=None):
    if scenario not in SCENARIOS or not re.fullmatch(r"cs-connection-[a-f0-9]{32}", run_id):
        raise ValueError("전용 시나리오/실행 ID 오류")
    if target is not None:
        addresses = [ipaddress.IPv4Address(value) for value in (target, client)]
        if addresses[0] == addresses[1] or any(
            not value.is_private or value.is_loopback or value.is_multicast or value.is_unspecified
            for value in addresses
        ):
            raise ValueError("소유 internal bridge의 서로 다른 IPv4 필요")


def configuration(scenario, run_id, role):
    return {
        "profile": PROFILE,
        "scenario": scenario,
        "run_id": run_id,
        "role": role,
        "port": PORT,
        "worker_pid": os.getpid(),
        "worker_start": Path("/proc/self/stat").read_text().split()[21],
    }


def split_http(raw, *, response):
    """합성 Content-Length 메시지만 경계로 자른다. PCAP/TCP 재조립기는 아니다.

    Why: recv 1회=메시지 1개 가정을 없애되 범용 HTTP 파서를 재발명하지 않는다.
    Constraints: 최대 버퍼 4096B·메시지 2048B·본문 256B, 중복 헤더/TE/비ASCII 거부.
    Side-effects: 순수 함수. 불완전 메시지는 None, 모순·상한은 예외로 전파한다.
    """
    if not isinstance(raw, bytes) or len(raw) > 4096:
        raise ValueError("HTTP 수신 버퍼 상한/형식 오류")
    boundary = raw.find(b"\r\n\r\n")
    if boundary < 0:
        if len(raw) >= 2048:
            raise ValueError("HTTP 헤더 상한 초과")
        return None
    head = raw[:boundary].decode("ascii", errors="strict").split("\r\n")
    if len(head) > 16:
        raise ValueError("합성 HTTP 헤더 개수 초과")
    pattern = r"HTTP/1\.1 (200 OK|403 Forbidden)" if response else r"GET /[1-3] HTTP/1\.1"
    if not re.fullmatch(pattern, head[0]):
        raise ValueError("합성 HTTP 시작 행 오류")
    headers = {}
    for line in head[1:]:
        key, sep, value = line.partition(": ")
        key = key.lower()
        if not sep or not re.fullmatch(r"[a-z-]{1,40}", key) or key in headers:
            raise ValueError("HTTP 헤더 형식/중복 오류")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("HTTP 헤더 제어문자 오류")
        headers[key] = value
    length = headers.get("content-length", "")
    if not re.fullmatch(r"0|[1-9][0-9]{0,2}", length) or int(length) > 256:
        raise ValueError("Content-Length 규격 오류")
    if "transfer-encoding" in headers or headers.get("connection") not in ("keep-alive", "close"):
        raise ValueError("합성 HTTP 프레이밍/연결 옵션 오류")
    size = boundary + 4 + int(length)
    if size > 2048:
        raise ValueError("HTTP 메시지 상한 초과")
    if len(raw) < size:
        return None
    return {
        "start_line": head[0],
        "headers": headers,
        "body_hex": raw[boundary + 4 : size].hex(),
        "header_bytes": boundary + 4,
        "bytes": size,
        "data_hex": raw[:size].hex(),
    }, raw[size:]


def http_bytes(run_id, ordinal, *, status=None, close=False):
    if ordinal not in (1, 2, 3) or status not in (None, 200, 403):
        raise ValueError("HTTP 메시지 순번/코드 오류")
    body = b"" if status is None else f"synthetic-{ordinal}\n".encode()
    first = (
        f"GET /{ordinal} HTTP/1.1"
        if status is None
        else (f"HTTP/1.1 {status} " + ("OK" if status == 200 else "Forbidden"))
    )
    headers = (
        f"{first}\r\nHost: local.test\r\nX-Run-ID: {run_id}\r\nX-Sequence: {ordinal}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: {'close' if close else 'keep-alive'}\r\n\r\n"
    )
    return headers.encode("ascii") + body


class Journal:
    """프로세스별 연결 번호와 실제 소켓 좌표를 묶어 FD 재사용을 연결 유지로 오인하지 않는다."""

    def __init__(self, scenario, run_id, role):
        self.scenario, self.run_id, self.role = scenario, run_id, role
        self.events = []
        self.identities = {}
        self.offsets = {}

    def opened(self, sock, connection):
        if connection in self.identities or connection not in (1, 2):
            raise ValueError("연결 번호 중복/상한 위반")
        local, remote = sock.getsockname(), sock.getpeername()
        self.identities[connection] = {
            "socket_id": f"{self.run_id}:{self.role}:{connection}",
            "fd": sock.fileno(),
            "pid": os.getpid(),
            "local_ip": local[0],
            "local_port": local[1],
            "remote_ip": remote[0],
            "remote_port": remote[1],
        }
        self.record(connection, "socket_open")

    def record(self, connection, event, *, data=None, **details):
        item = {
            "event_id": len(self.events) + 1,
            "connection": connection,
            **self.identities[connection],
            "event": event,
            "epoch": stamp(),
            "monotonic_ns": time.monotonic_ns(),
            **details,
        }
        if data is not None:
            if len(data) > (2048 if self.scenario.startswith("http_") else 256):
                raise ValueError("합성 메시지 상한 초과")
            direction = "send" if event in ("send", "response_send") else "receive"
            offset_key = (connection, direction)
            item.update(
                data_hex=data.hex(), bytes=len(data), stream_offset=self.offsets.get(offset_key, 0)
            )
            self.offsets[offset_key] = item["stream_offset"] + len(data)
        if (
            len(self.events) >= 64
            or len(json.dumps({**self.value(), "events": self.events + [item]}).encode())
            > LOG_BYTES
        ):
            raise ValueError("소켓 기록 64KiB/64개 이벤트 상한 초과")
        self.events.append(item)

    def value(self):
        return {
            "profile": PROFILE,
            "run_id": self.run_id,
            "scenario": self.scenario,
            "role": self.role,
            "events": self.events,
        }


def io_timeout(sock, deadline, *, connecting=False):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("클라이언트/서버 전체 시간 상한 초과")
    sock.settimeout(min(3 if connecting else 2, remaining))


def read_http(sock, buffer, deadline, *, response):
    while True:
        parsed = split_http(buffer[0], response=response)
        if parsed is not None:
            message, buffer[0] = parsed
            return message
        io_timeout(sock, deadline)
        chunk = sock.recv(2048)
        if not chunk:
            raise EOFError("HTTP 메시지 완료 전 EOF")
        buffer[0] += chunk


def receive_eof(sock, deadline, journal, connection):
    io_timeout(sock, deadline)
    if sock.recv(1) != b"":
        raise ValueError("EOF 대기 중 계획에 없는 데이터")
    journal.record(connection, "eof")


def shutdown_write(sock, journal, connection):
    sock.shutdown(socket.SHUT_WR)
    journal.record(connection, "shutdown_write")


def read_until_eof(sock, deadline, journal, connection):
    raw = b""
    while True:
        io_timeout(sock, deadline)
        chunk = sock.recv(257 - len(raw))
        if not chunk:
            journal.record(connection, "receive", data=raw)
            journal.record(connection, "eof")
            return raw
        raw += chunk
        if len(raw) > 256:
            raise ValueError("합성 TCP 수신 256바이트 초과")


def run_client(scenario, run_id, target, journal):
    deadline = time.monotonic() + 10
    groups = ((1, 2), (3,)) if scenario == "http_close" else ((1, 2, 3),)
    if not scenario.startswith("http_"):
        groups = ((1,),)
    for connection, ordinals in enumerate(groups, start=1):
        # connect는 계획된 연결마다 한 번만 호출한다. 실패 시 재연결·이름 조회는 하지 않는다.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            io_timeout(sock, deadline, connecting=True)
            sock.connect((target, PORT))
            journal.opened(sock, connection)
            if scenario.startswith("http_"):
                buffer = [b""]
                for ordinal in ordinals:
                    request = http_bytes(run_id, ordinal)
                    io_timeout(sock, deadline)
                    sock.sendall(request)
                    journal.record(connection, "send", data=request, ordinal=ordinal)
                    message = read_http(sock, buffer, deadline, response=True)
                    status = int(message["start_line"].split()[1])
                    journal.record(
                        connection,
                        "receive_http",
                        data=bytes.fromhex(message["data_hex"]),
                        ordinal=ordinal,
                        status=status,
                        headers=message["headers"],
                        header_bytes=message["header_bytes"],
                    )
                    expected = 403 if ordinal == 2 else 200
                    close = scenario == "http_close" and ordinal in (2, 3)
                    if (
                        status != expected
                        or message["headers"].get("x-run-id") != run_id
                        or (
                            message["headers"].get("x-sequence") != str(ordinal)
                            or message["headers"]["connection"]
                            != ("close" if close else "keep-alive")
                        )
                    ):
                        raise ValueError("HTTP 응답/실행/순번/종료 옵션 불일치")
                if buffer[0]:
                    raise ValueError("계획에 없는 HTTP 후속 바이트")
                if scenario == "http_close":
                    receive_eof(sock, deadline, journal, connection)
                    shutdown_write(sock, journal, connection)
                else:
                    shutdown_write(sock, journal, connection)
                    receive_eof(sock, deadline, journal, connection)
            elif scenario == "half_close":
                io_timeout(sock, deadline)
                sock.sendall(HALF_REQUEST)
                journal.record(connection, "send", data=HALF_REQUEST)
                shutdown_write(sock, journal, connection)
                if read_until_eof(sock, deadline, journal, connection) != HALF_RESPONSE:
                    raise ValueError("half-close 반대 방향 앱 수신 불일치")
            else:
                io_timeout(sock, deadline)
                sock.sendall(RESET_REQUEST)
                journal.record(connection, "send", data=RESET_REQUEST)
                io_timeout(sock, deadline)
                try:
                    data = sock.recv(256)
                except ConnectionResetError as exc:
                    if exc.errno != errno.ECONNRESET:
                        raise
                    journal.record(connection, "socket_reset", errno=exc.errno)
                else:
                    journal.record(connection, "unexpected_reset_result", data=data)
                    raise RuntimeError("명시적 RST 대신 EOF/데이터 수신")
            journal.record(connection, "socket_close")


def run_server(scenario, run_id, journal):
    deadline = time.monotonic() + 30
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("0.0.0.0", PORT))
        listener.listen(1)
        groups = ((1, 2), (3,)) if scenario == "http_close" else ((1, 2, 3),)
        if not scenario.startswith("http_"):
            groups = ((1,),)
        for connection, ordinals in enumerate(groups, start=1):
            listener.settimeout(max(0.001, deadline - time.monotonic()))
            accepted, _ = listener.accept()
            with accepted as sock:
                journal.opened(sock, connection)
                if scenario.startswith("http_"):
                    buffer = [b""]
                    for ordinal in ordinals:
                        message = read_http(sock, buffer, deadline, response=False)
                        raw = bytes.fromhex(message["data_hex"])
                        if raw != http_bytes(run_id, ordinal):
                            raise ValueError("서버의 합성 HTTP 요청 불일치")
                        journal.record(connection, "request_receive", data=raw, ordinal=ordinal)
                        status = 403 if ordinal == 2 else 200
                        close = scenario == "http_close" and ordinal in (2, 3)
                        response = http_bytes(run_id, ordinal, status=status, close=close)
                        io_timeout(sock, deadline)
                        sock.sendall(response)
                        journal.record(connection, "response_send", data=response, ordinal=ordinal)
                    if buffer[0]:
                        raise ValueError("계획에 없는 후속 요청")
                    if scenario == "http_close":
                        shutdown_write(sock, journal, connection)
                        receive_eof(sock, deadline, journal, connection)
                    else:
                        receive_eof(sock, deadline, journal, connection)
                        shutdown_write(sock, journal, connection)
                elif scenario == "half_close":
                    if read_until_eof(sock, deadline, journal, connection) != HALF_REQUEST:
                        raise ValueError("half-close 서버 수신 불일치")
                    io_timeout(sock, deadline)
                    sock.sendall(HALF_RESPONSE)
                    journal.record(connection, "response_send", data=HALF_RESPONSE)
                    shutdown_write(sock, journal, connection)
                else:
                    raw = b""
                    while len(raw) < len(RESET_REQUEST):
                        io_timeout(sock, deadline)
                        chunk = sock.recv(len(RESET_REQUEST) - len(raw))
                        if not chunk:
                            raise EOFError("RST 준비 전 조기 EOF")
                        raw += chunk
                    if (
                        raw != RESET_REQUEST
                        or sys.platform != "linux"
                        or struct.calcsize("ii") != 8
                    ):
                        raise ValueError("Linux linger/합성 메시지 제약 위반")
                    journal.record(connection, "receive", data=raw)
                    linger = struct.pack("ii", 1, 0)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                    actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER, len(linger))
                    if actual != linger:
                        raise RuntimeError("linger 적용 검증 실패")
                    journal.record(connection, "abortive_close", linger_hex=actual.hex())
                journal.record(connection, "socket_close")


def serve(scenario, run_id):
    validate(scenario, run_id)
    save(DIRECTORY / "server-config.json", configuration(scenario, run_id, "server"))
    journal = Journal(scenario, run_id, "server")
    result = {"run_id": run_id, "scenario": scenario, "complete": False, "error": None}
    try:
        run_server(scenario, run_id, journal)
        result["complete"] = True
    except (Exception, KeyboardInterrupt) as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        save(DIRECTORY / "server.json", journal.value())
        save(DIRECTORY / "server-result.json", result)
    return 0 if result["complete"] else 1


def capture_file_limit():
    """로그별 하드 상한을 위해 캡처 자식의 모든 파일을 더 작은 64KiB로 제한한다.

    합성 트래픽은 수 KiB이며 PCAP 1MiB 상한도 충족한다. 포화 시 수집 실패로 처리한다.
    """
    import resource

    file_limit()
    resource.setrlimit(resource.RLIMIT_FSIZE, (LOG_BYTES, LOG_BYTES))


def trial(scenario, target, client, run_id):
    validate(scenario, run_id, target, client)
    config = {
        **configuration(scenario, run_id, "client"),
        "target": target,
        "client": client,
        "capture_seconds": CAPTURE_SECONDS,
        "packets": PACKETS,
        "file_bytes": FILE_BYTES,
        "requests": 3 if scenario.startswith("http_") else 0,
        "connections": 2 if scenario == "http_close" else 1,
        "concurrency": 1,
        "connect_seconds": 3,
        "io_seconds": 2,
        "client_seconds": 10,
        "capture_file_rlimit_bytes": LOG_BYTES,
    }
    save(DIRECTORY / "config.json", config)
    journal = Journal(scenario, run_id, "client")
    result = {
        "run_id": run_id,
        "scenario": scenario,
        "worker_complete": False,
        "error": None,
        "capture": {"started_epoch": stamp()},
    }
    capture = None
    try:
        with (
            (DIRECTORY / "capture.stdout").open("xb") as out,
            (DIRECTORY / "capture.stderr").open("xb") as err,
        ):
            capture = subprocess.Popen(
                [
                    "bash",
                    "/opt/network/tcpdump_capture.sh",
                    target,
                    str(PORT),
                    "eth0",
                    str(DIRECTORY / "capture.pcap"),
                    str(CAPTURE_SECONDS),
                    str(PACKETS),
                ],
                stdout=out,
                stderr=err,
                start_new_session=True,
                preexec_fn=capture_file_limit,
            )
            ready = time.monotonic() + 3
            while True:
                log = (DIRECTORY / "capture.stderr").read_bytes()
                if len(log) > LOG_BYTES or capture.poll() is not None:
                    raise RuntimeError("캡처 준비 전 종료/로그 상한")
                if b"listening on eth0" in log:
                    break
                if time.monotonic() >= ready:
                    raise TimeoutError("캡처 준비 3초 초과")
                time.sleep(0.02)
            result["capture"]["ready_epoch"] = stamp()
            run_client(scenario, run_id, target, journal)
            deadline = time.monotonic() + CAPTURE_SECONDS + 3
            while capture.poll() is None:
                if any(
                    (DIRECTORY / name).stat().st_size > LOG_BYTES
                    for name in ("capture.stdout", "capture.stderr")
                ):
                    raise ValueError("캡처 로그 64KiB 초과")
                if time.monotonic() >= deadline:
                    raise TimeoutError("캡처 종료 시간 상한 초과")
                time.sleep(0.02)
            result["capture"]["exit"] = capture.wait(timeout=1)
        log = (DIRECTORY / "capture.stderr").read_text()
        dropped = re.search(r"(?m)^(\d+) packets dropped by kernel$", log)
        captured = re.search(r"(?m)^(\d+) packets captured$", log)
        result["capture"].update(
            kernel_dropped=int(dropped[1]) if dropped else None,
            packets=int(captured[1]) if captured else None,
        )
        if (
            result["capture"]["exit"] != 124
            or "시간 제한 도달" not in log
            or not dropped
            or int(dropped[1]) != 0
            or not captured
            or not 0 < int(captured[1]) < PACKETS
            or not 24 < (DIRECTORY / "capture.pcap").stat().st_size <= FILE_BYTES
        ):
            raise RuntimeError("캡처 실패/누락/절단: 정상 종료 판정 금지")
        result["worker_complete"] = True
    except (Exception, KeyboardInterrupt) as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        if capture is not None:
            try:
                stop(capture)
            except (OSError, subprocess.SubprocessError) as exc:
                result["worker_complete"] = False
                result["cleanup_error"] = type(exc).__name__ + ": " + str(exc)
        result["capture"]["ended_epoch"] = stamp()
        save(DIRECTORY / "client.json", journal.value())
        save(DIRECTORY / "worker-result.json", result)
    return 0 if result["worker_complete"] else 1


def quiescent(run_id, role):
    name = "server-config.json" if role == "server" else "config.json"
    config = json.loads((DIRECTORY / name).read_text())
    if config["run_id"] != run_id or config["role"] != role:
        raise ValueError("다른 실행/역할의 worker")
    try:
        fields = Path(f"/proc/{config['worker_pid']}/stat").read_text().split()
    except FileNotFoundError:
        return 0
    return int(fields[21] == config["worker_start"] and fields[2] != "Z")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    server = commands.add_parser("serve")
    server.add_argument("scenario", choices=SCENARIOS)
    server.add_argument("run_id")
    client = commands.add_parser("trial")
    client.add_argument("scenario", choices=SCENARIOS)
    client.add_argument("target")
    client.add_argument("client")
    client.add_argument("run_id")
    quiet = commands.add_parser("quiescent")
    quiet.add_argument("run_id")
    quiet.add_argument("role", choices=("server", "client"))
    args = parser.parse_args(argv)

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("사용자/상위 프로세스 중단")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if args.action == "quiescent":
        return quiescent(args.run_id, args.role)
    if args.action == "serve":
        return serve(args.scenario, args.run_id)
    return trial(args.scenario, args.target, args.client, args.run_id)


if __name__ == "__main__":
    raise SystemExit(main())
