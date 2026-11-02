"""기존 데모 도구를 호출하는 유한 SSH 어댑터. AWS SDK·자격증명을 사용하지 않는다.

Why: 캡처 수명과 기존 공격 러너 수명을 분리하되 공격/패킷 해석 로직은 재구현하지 않는다.
Constraints: root 전용 새 실행 경로, 기존 자산 해시, 120초/2000패킷, 원본 최대 32개.
Side-effects: start/attack/probe/stop은 명시적 실행 요청에서만 사용한다. 자기 PID만 정리한다.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

MAX_BYTES = 1024 * 1024
ASSETS = {
    "demo_attack_runner.sh",
    "demo_attack_runner.py",
    "ec2_hydra_measurement.py",
    "web_dir_scan.sh",
    "tcpdump_capture.sh",
    "roundtrip_timeline.py",
    "sg_connection_timeline.py",
    "waf_packet_timeline.py",
}


def stamp():
    return datetime.now(UTC).isoformat()


def save(path, value):
    raw = (json.dumps(value, ensure_ascii=False) + "\n").encode()
    if len(raw) > MAX_BYTES:
        raise ValueError("원격 메타데이터 상한")
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".controller-")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.link(temporary, path)
    finally:
        Path(temporary).unlink()


def read(path):
    if path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise ValueError("원격 입력 경로/상한")
    return json.loads(path.read_bytes())


def process_ticks(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return None if raw[0] == "Z" else raw[19]
    except FileNotFoundError:
        return None


def stop_owned(entries, directory):
    """PID 재사용과 타 실행 정리를 막는다. 저장한 시작 tick과 명령 경로를 함께 확인한다."""
    forced = []
    for item in entries:
        pid = item["pid"]
        if item["ticks"] is None or process_ticks(pid) != item["ticks"]:
            continue
        command = Path(f"/proc/{pid}/cmdline").read_bytes()
        if str(directory).encode() not in command:
            raise ValueError("소유 캡처 명령 불일치")
        os.killpg(pid, signal.SIGTERM)
        deadline = time.monotonic() + 3
        while process_ticks(pid) == item["ticks"] and time.monotonic() < deadline:
            time.sleep(0.1)
        if process_ticks(pid) == item["ticks"]:
            os.killpg(pid, signal.SIGKILL)
            forced.append(pid)
    return forced


def dispatch(request):
    allowed = {
        "op",
        "root",
        "assets",
        "run_id",
        "scenario",
        "approval",
        "target_ip",
        "origin",
        "interface",
        "attacker_instance_id",
        "account_id",
        "region",
        "source_ip",
    }
    if set(request) - allowed:
        raise ValueError("원격 요청에 미허용 필드")
    root = Path(request["root"])
    if not re.fullmatch(r"/home/ubuntu/cloudshield-p5-4-prep-[A-Za-z0-9-]+", str(root)):
        raise ValueError("준비 경로 오류")
    if root.is_symlink() or not root.is_dir() or os.geteuid() != 0:
        raise ValueError("원격 실행 사용자/경로 오류")
    if set(request["assets"]) != ASSETS:
        raise ValueError("기존 자산 목록 불일치")
    for name, expected in request["assets"].items():
        path = root / "network" / name
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size > MAX_BYTES
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected
        ):
            raise ValueError("기존 자산 해시 불일치")
    sys.path.insert(0, str(root / "network"))
    import demo_attack_runner as runner
    import ec2_hydra_measurement as ssh

    operation = request["op"]
    if operation == "preflight":
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        token = (
            opener.open(
                urllib.request.Request(
                    "http://169.254.169.254/latest/api/token",
                    data=b"",
                    method="PUT",
                    headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
                ),
                timeout=3,
            )
            .read()
            .decode()
        )

        def metadata(path):
            return opener.open(
                urllib.request.Request(
                    "http://169.254.169.254/latest/" + path,
                    headers={"X-aws-ec2-metadata-token": token},
                ),
                timeout=3,
            ).read()

        identity = json.loads(metadata("dynamic/instance-identity/document"))
        public_ip = metadata("meta-data/public-ipv4").decode()
        matches = (
            identity["instanceId"] == request["attacker_instance_id"]
            and identity["accountId"] == request["account_id"]
            and identity["region"] == request["region"]
            and public_ip == request["source_ip"]
        )
        runner.private_root(root / "root-evidence")
        ssh.validate_interface(request["interface"])
        return {
            "identity_matches": matches,
            "uid": os.geteuid(),
            "python": sys.version.split()[0],
            "hydra": ssh.check_hydra(ssh.require_tool("hydra")),
            "time": stamp(),
        }

    run_id, scenario = request["run_id"], request["scenario"]
    if not re.fullmatch(r"[A-Za-z0-9-]{1,80}", run_id) or scenario not in {"ssh", "web"}:
        raise ValueError("실행 식별자 오류")
    parent = runner.private_root(root / "root-evidence") / run_id
    directory = parent / scenario
    if operation == "start":
        approval = runner.parse_approval(request["approval"], scenario)
        if approval.source_ipv4 != request["source_ip"]:
            raise ValueError("승인 출발지 불일치")
        if scenario == "ssh" and approval.ec2_ip != request["target_ip"]:
            raise ValueError("승인 타깃 불일치")
        if scenario == "web" and approval.alb_origin != request["origin"]:
            raise ValueError("승인 origin 불일치")
        parent.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700)
        (directory / "runner").mkdir(mode=0o700)
        if scenario == "ssh":
            addresses = [request["target_ip"]]
        else:
            host = runner.urlsplit(request["origin"]).hostname
            addresses = sorted({r[4][0] for r in socket.getaddrinfo(host, 80, socket.AF_INET)})
            if not 1 <= len(addresses) <= 2:
                raise ValueError("ALB 주소 개수 상한")
        entries = []
        try:
            for index, address in enumerate(addresses):
                ipaddress.IPv4Address(address)
                stderr = directory / f"capture-{index}.stderr"
                with stderr.open("xb") as err:
                    process = subprocess.Popen(
                        [
                            "bash",
                            str(root / "network/tcpdump_capture.sh"),
                            address,
                            "22" if scenario == "ssh" else "80",
                            request["interface"],
                            str(directory / f"capture-{index}.pcap"),
                            "120",
                            "2000",
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=err,
                        start_new_session=True,
                    )
                entry = {"pid": process.pid, "ticks": process_ticks(process.pid)}
                entries.append(entry)
                save(directory / f"capture-owner-{index}.json", entry)
                deadline = time.monotonic() + 5
                while b"listening on" not in stderr.read_bytes():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("캡처 준비 미확인")
                    time.sleep(0.1)
            result = {"started_at": stamp(), "addresses": addresses, "processes": entries}
            save(directory / "capture-start.json", result)
            return result
        except BaseException:
            stop_owned(entries, directory)
            raise

    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("해당 실행 경로 없음")
    if operation == "attack":
        approval = runner.parse_approval(request["approval"], scenario)
        owners = read(directory / "capture-start.json")["processes"]
        if any(process_ticks(p["pid"]) != p["ticks"] for p in owners):
            raise RuntimeError("공격 전 캡처 중단")
        save(directory / "attack-attempted.json", {"time": stamp()})
        approval_path = root / "root-approval" / f"{run_id}-{scenario}.json"
        save(approval_path, request["approval"])
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("AWS_") and k != "SLACK_WEBHOOK_URL"
        }
        env.update(
            PATH=str(root / "runtime/python/bin") + ":" + env.get("PATH", ""),
            CLOUDSHIELD_PIPELINE_READY="yes",
            CLOUDSHIELD_SOURCE_ALLOWED="yes",
            CLOUDSHIELD_RECOVERY_READY="yes",
            CLOUDSHIELD_TARGET_IP=request["target_ip"],
            CLOUDSHIELD_TEST_ACCOUNT="cloudshield_test",
        )
        command = [
            "bash",
            str(root / "network/demo_attack_runner.sh"),
            "--scenario",
            scenario,
            "--execute",
            "--approval-file",
            str(approval_path),
            "--evidence-root",
            str(directory / "runner"),
            "--interface",
            request["interface"],
        ]
        started = stamp()
        with (directory / "runner.stdout").open("xb") as out:
            with (directory / "runner.stderr").open("xb") as err:
                process = subprocess.Popen(
                    command,
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                    start_new_session=True,
                )
                save(
                    directory / "attack-process.json",
                    {
                        "pid": process.pid,
                        "ticks": process_ticks(process.pid),
                    },
                )
                try:
                    code = process.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=3)
                    code = 124
        children = list((directory / "runner").iterdir())
        child_id = children[0].name if len(children) == 1 else None
        result = {
            "exit_code": code,
            "started_at": started,
            "ended_at": stamp(),
            "runner_run_id": child_id,
        }
        save(directory / "attack-result.json", result)
        return result
    if operation == "stop_attack":
        owner = directory / "attack-process.json"
        forced = stop_owned([read(owner)], directory) if owner.exists() else []
        return {"attack_quiesced": True, "forced_kill_count": len(forced)}
    if operation == "probe":
        if scenario == "ssh":
            return ssh.probe_once(request["target_ip"])
        children = runner.Children()
        try:
            return runner.http_probe(request["origin"], children)
        finally:
            children.cleanup()
    if operation == "stop":
        owners = [read(p) for p in directory.glob("capture-owner-*.json")]
        already_stopped = sum(
            p["ticks"] is None or process_ticks(p["pid"]) != p["ticks"] for p in owners
        )
        forced = stop_owned(owners, directory)
        result = {
            "stopped_at": stamp(),
            "forced_kill_count": len(forced),
            "capture_already_stopped_count": already_stopped,
        }
        save(directory / "capture-stop.json", result)
        return result
    if operation == "manifest":
        records = []
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ValueError("원격 증거 링크 거부")
            if not path.is_file():
                continue
            size = path.stat().st_size
            if size > (1024**3 if path.suffix == ".pcap" else MAX_BYTES):
                raise ValueError("원격 증거 파일 상한")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(MAX_BYTES), b""):
                    digest.update(chunk)
            records.append(
                {
                    "path": path.relative_to(directory).as_posix(),
                    "bytes": size,
                    "sha256": digest.hexdigest(),
                }
            )
            if len(records) > 32:
                raise ValueError("원격 증거 파일 개수 상한")
        return {"files": records}
    raise ValueError("지원하지 않는 원격 동작")


def main():
    raw = sys.stdin.buffer.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("원격 요청 상한")
    print(json.dumps(dispatch(json.loads(raw)), ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"remote_error": type(exc).__name__}))
        raise SystemExit(2) from None
