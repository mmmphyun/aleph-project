"""컨테이너 내부의 단일 합성 요청과 유한 캡처. import는 부작용이 없다.

Why: 클라이언트 timeout과 캡처 실패를 분리하고 기존 캡처 스크립트를 그대로 사용한다.
Constraints: TCP 8080, 요청 1회, 8초/256패킷/PCAP 1MiB, 로그별 64KiB.
Side-effects: serve/trial 명령에서만 로컬 소켓·소유 자식을 만들며 실패·중단을 전파한다.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SCENARIOS = ("normal", "drop", "rst", "http403")
PORT = 8080
CAPTURE_SECONDS = 8
PACKETS = 256
FILE_BYTES = 1024 * 1024
LOG_BYTES = 65536
DIRECTORY = Path("/run/evidence")


def stamp():
    value = time.time_ns()
    return f"{value // 1_000_000_000}.{value % 1_000_000_000:09d}"


def save(path, value):
    """실패 회차의 부분 파일도 지우지 않는다. 완성 여부는 별도 결과로 기록한다."""
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    if len(raw) > FILE_BYTES:
        raise ValueError("메타데이터 상한 초과")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def file_limit():
    # 자식별 OS 상한으로 캡처 폭주를 멈춘다. SIGXFSZ를 정상 무응답으로 처리하지 않는다.
    import resource

    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_BYTES, FILE_BYTES))


def stop(process):
    """새 세션으로 만든 소유 프로세스 그룹만 TERM 2초/KILL 1초로 회수한다."""
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)


def validate(scenario, target, client, run_id):
    if scenario not in SCENARIOS or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", run_id):
        raise ValueError("시나리오/실행 ID 오류")
    addresses = [ipaddress.IPv4Address(item) for item in (target, client)]
    if any(not item.is_private or item.is_loopback for item in addresses):
        raise ValueError("전용 컨테이너 주소만 허용")
    if addresses[0] == addresses[1]:
        raise ValueError("서버/클라이언트 주소 중복")


def curl_argv(target):
    # curl 설정·프록시·리다이렉트·재시도를 차단해 한 회차를 신규 연결 한 번으로 고정한다.
    return [
        "curl",
        "-q",
        "--ipv4",
        "--http1.1",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--proxy",
        "",
        "--max-redirs",
        "0",
        "--retry",
        "0",
        "--connect-timeout",
        "4",
        "--max-time",
        "5",
        "--max-filesize",
        "1024",
        "--header",
        "Connection: close",
        "--output",
        str(DIRECTORY / "body.txt"),
        "--dump-header",
        str(DIRECTORY / "headers.txt"),
        "--write-out",
        "%{http_code}|%{local_ip}|%{local_port}|%{remote_ip}|%{remote_port}|"
        "%{time_connect}|%{time_total}",
        "--",
        f"http://{target}:{PORT}/",
    ]


def probe(target):
    paths = [DIRECTORY / "curl.stdout", DIRECTORY / "curl.stderr"]
    before = stamp()
    with paths[0].open("xb") as out, paths[1].open("xb") as err:
        process = subprocess.Popen(
            curl_argv(target),
            stdout=out,
            stderr=err,
            start_new_session=True,
            preexec_fn=file_limit,
        )
        try:
            code = process.wait(timeout=6)
        finally:
            stop(process)
    if any(path.stat().st_size > LOG_BYTES for path in paths):
        raise ValueError("클라이언트 로그 상한 초과")
    fields = paths[0].read_text().split("|")
    if code not in (0, 7, 28) or len(fields) != 7:
        raise RuntimeError(f"클라이언트 도구 실패: exit={code}")
    status, local, local_port, remote, remote_port, connect, total = fields
    if not re.fullmatch(r"[0-9]{3}", status):
        raise ValueError("클라이언트 상태 형식 오류")
    return {
        "exit": code,
        "reason": {0: "http_response", 7: "connect_error", 28: "timeout"}[code],
        "http_status": int(status),
        "local_ip": local,
        "local_port": int(local_port),
        "remote_ip": remote,
        "remote_port": int(remote_port),
        "connect_seconds": connect,
        "total_seconds": total,
        "started_epoch": before,
        "ended_epoch": stamp(),
    }


def trial(scenario, target, client, run_id):
    validate(scenario, target, client, run_id)
    result = {
        "scenario": scenario,
        "run_id": run_id,
        "worker_complete": False,
        "error": None,
        "client": None,
        "capture": {"started_epoch": stamp()},
    }
    save(
        DIRECTORY / "config.json",
        {
            "scenario": scenario,
            "target": target,
            "client": client,
            "port": PORT,
            "run_id": run_id,
            "capture_seconds": CAPTURE_SECONDS,
            "packets": PACKETS,
            "file_bytes": FILE_BYTES,
            "requests": 1,
            "concurrency": 1,
            "worker_pid": os.getpid(),
            "worker_start": Path("/proc/self/stat").read_text().split()[21],
        },
    )
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
                preexec_fn=file_limit,
            )
            deadline = time.monotonic() + 3
            while True:
                raw = (DIRECTORY / "capture.stderr").read_bytes()
                if len(raw) > LOG_BYTES or capture.poll() is not None:
                    raise RuntimeError("캡처 준비 전 종료/로그 상한 초과")
                if b"listening on eth0" in raw:
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError("캡처 준비 3초 초과")
                time.sleep(0.02)
            result["capture"]["ready_epoch"] = stamp()
            result["client"] = probe(target)
            result["capture"]["exit"] = capture.wait(timeout=9)
        capture_info = result["capture"]
        capture_info["ended_epoch"] = stamp()
        log = (DIRECTORY / "capture.stderr").read_bytes()
        if len(log) > LOG_BYTES:
            raise ValueError("캡처 로그 상한 초과")
        text = log.decode("utf-8", errors="strict")
        dropped = re.search(r"(?m)^(\d+) packets dropped by kernel$", text)
        captured = re.search(r"(?m)^(\d+) packets captured$", text)
        capture_info["kernel_dropped"] = int(dropped[1]) if dropped else None
        capture_info["packets"] = int(captured[1]) if captured else None
        if (
            capture_info["exit"] != 124
            or "시간 제한 도달" not in text
            or capture_info["kernel_dropped"] != 0
            or not captured
            or not 0 < int(captured[1]) < PACKETS
        ):
            raise RuntimeError("캡처 실패/누락/패킷 상한 도달: 무응답 판정 금지")
        size = (DIRECTORY / "capture.pcap").stat().st_size
        if not 24 < size <= FILE_BYTES:
            raise ValueError("PCAP 없음/용량 상한 초과")
        result["worker_complete"] = True
    except (Exception, KeyboardInterrupt) as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        if capture is not None:
            try:
                stop(capture)
            except (OSError, subprocess.SubprocessError) as exc:
                result["worker_complete"] = False
                result["cleanup_error"] = str(exc)
        result["capture"]["ended_epoch"] = stamp()
        save(DIRECTORY / "worker-result.json", result)
    return 0 if result["worker_complete"] else 1


def serve(status):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = b"local synthetic response\n"
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
            self.close_connection = True

        def log_message(self, *_args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(3)

    with HTTPServer(("0.0.0.0", PORT), Handler) as server:
        server.serve_forever()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    server = commands.add_parser("serve")
    server.add_argument("status", type=int, choices=(200, 403))
    client = commands.add_parser("trial")
    client.add_argument("scenario", choices=SCENARIOS)
    client.add_argument("target")
    client.add_argument("client")
    client.add_argument("run_id")
    quiet = commands.add_parser("quiescent")
    quiet.add_argument("run_id")
    args = parser.parse_args(argv)
    if args.action == "quiescent":
        config = json.loads((DIRECTORY / "config.json").read_text())
        if config["run_id"] != args.run_id:
            raise ValueError("다른 실행의 worker")
        path = Path(f"/proc/{config['worker_pid']}/stat")
        try:
            fields = path.read_text().split()
        except FileNotFoundError:
            return 0
        return int(fields[21] == config["worker_start"] and fields[2] != "Z")

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("사용자/상위 프로세스 중단")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    if args.action == "serve":
        serve(args.status)
        return 0
    return trial(args.scenario, args.target, args.client, args.run_id)


if __name__ == "__main__":
    raise SystemExit(main())
