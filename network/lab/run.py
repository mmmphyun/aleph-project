"""명시적 build/run 전용 Docker 실험. import 및 기본 pytest는 외부 명령을 실행하지 않는다."""

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "cloudshield-network-ssh-lab:local"
LABEL = "cloudshield.network.lab"
PORT = "2222"


class Lab:
    def __init__(self, output):
        # UUID 경로를 독점 생성하여 기존 증거를 덮어쓰지 않는다.
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=False)
        self.run_id = "cs-ssh-" + uuid.uuid4().hex
        self.containers = []
        self.retained_containers = set()
        self.network = None
        self.events = []
        self.env = os.environ.copy()
        for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            self.env.pop(name, None)
        self.context = None

    def call(self, *args, check=True, data=None, timeout=30):
        command = ["docker"]
        if self.context:
            command += ["--context", self.context]
        command += list(args)
        result = subprocess.run(
            command,
            input=data,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=self.env,
            check=False,
        )
        # stdin에는 공개 키만 전달하지만 기본적으로 기록에서 제외한다.
        self.events.append(
            {
                "command": command,
                "code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "utc": datetime.now(UTC).isoformat(),
            }
        )
        if check and result.returncode:
            raise RuntimeError(f"Docker 실패: {args[0]}: {result.stderr}")
        return result

    def preflight(self):
        self.context = self.call("context", "show").stdout.strip()
        context = json.loads(self.call("context", "inspect", self.context).stdout)[0]
        endpoint = context["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith(("npipe://", "unix://")):
            raise RuntimeError("로컬 npipe/unix Docker 엔진만 허용합니다.")
        info = json.loads(self.call("info", "--format", "{{json .}}").stdout)
        if info["OSType"] != "linux":
            raise RuntimeError("Linux 컨테이너 엔진이 필요합니다.")
        self.call("version")

    def create(self, role):
        name = self.run_id + "-" + role
        caps = (
            ["NET_RAW"]
            if role == "client"
            else [
                "SETUID",
                "SETGID",
                "SYS_CHROOT",
            ]
        )
        args = [
            "create",
            "--name",
            name,
            "--label",
            f"{LABEL}={self.run_id}",
            "--network",
            self.network,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "64",
            "--memory",
            "256m",
        ]
        for cap in caps:
            args += ["--cap-add", cap]
        args += [IMAGE]
        args += ["bash", "/opt/lab/server.sh"] if role == "server" else ["sleep", "infinity"]
        # 성공한 create의 정확한 ID만 정리 대상으로 등록한다.
        cid = self.call(*args).stdout.strip()
        self.containers.append(cid)
        self.call("start", cid)
        return cid

    def inspect_ip(self, cid):
        item = json.loads(self.call("inspect", cid).stdout)[0]
        networks = item["NetworkSettings"]["Networks"]
        if len(networks) != 1 or item["HostConfig"].get("PortBindings"):
            raise RuntimeError("단일 내부 네트워크/포트 비공개 조건 위반")
        ip = next(iter(networks.values()))["IPAddress"]
        return str(ipaddress.IPv4Address(ip))

    def wait_listener(self, server):
        # TCP 연결을 만들지 않고 서버 네임스페이스의 LISTEN 상태만 확인한다.
        for _ in range(50):
            result = self.call("exec", server, "ss", "-H", "-lnt", "sport = :2222")
            if result.stdout.strip():
                return
            time.sleep(0.1)
        raise RuntimeError("SSH LISTEN 준비 시간 초과; SSH 실행하지 않음")

    def capture(self, client, server_ip, interface):
        args = [
            "docker",
            "--context",
            self.context,
            "exec",
            client,
            "bash",
            "/opt/network/tcpdump_capture.sh",
            server_ip,
            PORT,
            interface,
            "/tmp/capture.pcap",
            "10",
            "1000",
        ]
        self.events.append({"capture_command": args, "utc": datetime.now(UTC).isoformat()})
        with (
            (self.output / "capture.stdout").open("xb") as out,
            (self.output / "capture.stderr").open("xb") as err,
        ):
            proc = subprocess.Popen(args, stdout=out, stderr=err, env=self.env)
            try:
                for _ in range(50):
                    log = (self.output / "capture.stderr").read_text(errors="replace")
                    if proc.poll() is not None:
                        raise RuntimeError("캡처가 준비 전에 종료되어 SSH 실행하지 않음")
                    if "listening on " in log:
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("캡처 준비 확인 실패; SSH 실행하지 않음")
                self.events.append({"capture_ready_utc": datetime.now(UTC).isoformat()})
                # OpenSSH는 passwd의 홈 경로를 사용한다. lab UID와 HOME을 함께 고정한다.
                ssh = self.call(
                    "exec",
                    "--user",
                    "lab",
                    "--env",
                    "HOME=/home/lab",
                    client,
                    "timeout",
                    "15",
                    "bash",
                    "/opt/network/ssh_single_connect.sh",
                    server_ip,
                    "lab",
                    PORT,
                    "5",
                    check=False,
                    timeout=20,
                )
                (self.output / "ssh.stderr").write_text(ssh.stderr, encoding="utf-8")
                (self.output / "ssh.stdout").write_text(ssh.stdout, encoding="utf-8")
                code = proc.wait(timeout=15)
                self.events.append({"capture_exit": code, "ssh_exit": ssh.returncode})
                if code not in (0, 124) or ssh.returncode:
                    raise RuntimeError("SSH/캡처 실패: 종료 코드와 stderr를 확인하세요.")
            finally:
                # docker exec CLI만 종료하면 원격 프로세스가 남을 수 있다. 컨테이너의
                # 10초 자체 제한을 먼저 기다리고 최종 정리에서 소유 컨테이너만 제거한다.
                if proc.poll() is None:
                    try:
                        proc.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                        proc.wait(timeout=5)
                self.events.append({"capture_final_exit": proc.returncode})

    def preserve(self, client):
        # 복사가 실패하면 원본 pcap을 가진 컨테이너를 자동 삭제하지 않는다.
        self.retained_containers.add(client)
        destination = self.output / "capture.pcap"
        if destination.exists():
            raise RuntimeError("기존 pcap 보존: 덮어쓰기 금지")
        result = self.call("cp", f"{client}:/tmp/capture.pcap", str(destination), check=False)
        if result.returncode == 0:
            raw = destination.read_bytes()
            self.retained_containers.discard(client)
            read = self.call(
                "exec", client, "tcpdump", "-nn", "-r", "/tmp/capture.pcap", check=False
            )
            (self.output / "tcpdump-read.txt").write_text(read.stdout, encoding="utf-8")
            self.events.append(
                {
                    "pcap": str(destination),
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "read_exit": read.returncode,
                }
            )
            if read.returncode or not read.stdout.strip():
                raise RuntimeError("pcap 읽기 실패 또는 패킷 없음; 실측 성공 아님")
        else:
            raise RuntimeError("pcap 확보 실패; 증거 없음")

    def experiment(self):
        image = json.loads(self.call("image", "inspect", IMAGE).stdout)[0]
        if image["Config"].get("Labels", {}).get(LABEL) != "ssh-single-v1":
            raise RuntimeError("전용 lab 이미지가 아닙니다. build를 먼저 실행하세요.")
        self.network = self.call(
            "network",
            "create",
            "--internal",
            "--driver",
            "bridge",
            "--label",
            f"{LABEL}={self.run_id}",
            self.run_id,
        ).stdout.strip()
        net = json.loads(self.call("network", "inspect", self.network).stdout)[0]
        if not net["Internal"]:
            raise RuntimeError("내부 네트워크 조건 위반")
        server = self.create("server")
        client = self.create("client")
        capture_attempted = False
        try:
            self.wait_listener(server)
            server_ip, client_ip = self.inspect_ip(server), self.inspect_ip(client)
            route = json.loads(
                self.call("exec", client, "ip", "-j", "route", "get", server_ip).stdout
            )[0]
            interface = route["dev"]
            if route.get("prefsrc") != client_ip:
                raise RuntimeError("캡처 출발 IP/경로 불일치")
            self.call(
                "exec",
                "--user",
                "lab",
                client,
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                "/home/lab/.ssh/id_ed25519",
            )
            public = self.call("exec", client, "cat", "/home/lab/.ssh/id_ed25519.pub").stdout
            self.call(
                "exec",
                "-i",
                "--user",
                "lab",
                server,
                "bash",
                "-c",
                "umask 077; cat > /home/lab/.ssh/authorized_keys",
                data=public,
            )
            host = self.call("exec", server, "cat", "/etc/ssh/ssh_host_ed25519_key.pub").stdout
            known = f"[{server_ip}]:{PORT} " + " ".join(host.split()[:2]) + "\n"
            self.call(
                "exec",
                "-i",
                "--user",
                "lab",
                client,
                "bash",
                "-c",
                "umask 077; cat > /home/lab/.ssh/known_hosts",
                data=known,
            )
            for command in (
                ["uname", "-a"],
                ["tcpdump", "--version"],
                ["ssh", "-V"],
                ["cat", "/etc/os-release"],
            ):
                self.call("exec", client, *command)
            self.events.append(
                {
                    "server_ip": server_ip,
                    "client_ip": client_ip,
                    "port": PORT,
                    "interface": interface,
                    "readiness_tcp_connections": 0,
                }
            )
            capture_attempted = True
            self.capture(client, server_ip, interface)
        finally:
            primary_error = sys.exception()
            archive_errors = []
            archives = [lambda: self.call("logs", server, check=False)]
            if capture_attempted:
                archives.append(lambda: self.preserve(client))
            for archive in archives:
                try:
                    archive()
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    archive_errors.append(str(exc))
            self.events.append({"archive_errors": archive_errors})
            if archive_errors and primary_error is None:
                raise RuntimeError("; ".join(archive_errors))

    def cleanup(self):
        failures = []
        for cid in reversed(self.containers):
            if cid in self.retained_containers:
                failures.append(cid)
                continue
            try:
                if self.call("rm", "-f", cid, check=False).returncode:
                    failures.append(cid)
            except (OSError, subprocess.SubprocessError) as exc:
                failures.append(f"{cid}: {exc}")
        if self.network:
            if self.retained_containers:
                failures.append(self.network)
                return failures
            try:
                if self.call("network", "rm", self.network, check=False).returncode:
                    failures.append(self.network)
            except (OSError, subprocess.SubprocessError) as exc:
                failures.append(f"{self.network}: {exc}")
        return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["build", "run"])
    args = parser.parse_args()
    output = (
        ROOT
        / "network/lab/runs"
        / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])
    )
    lab = Lab(output)
    status = 1
    error = None
    try:
        if not shutil.which("docker"):
            raise RuntimeError("Docker CLI 없음: 시스템 설치 승인 후 준비하세요.")
        lab.preflight()
        if args.action == "build":
            lab.call(
                "build",
                "--label",
                f"{LABEL}=ssh-single-v1",
                "-t",
                IMAGE,
                "-f",
                str(ROOT / "network/lab/Dockerfile"),
                str(ROOT / "network"),
                timeout=1800,
            )
        else:
            lab.experiment()
        status = 0
    except (
        OSError,
        RuntimeError,
        ValueError,
        subprocess.SubprocessError,
        KeyboardInterrupt,
    ) as exc:
        error = str(exc) or type(exc).__name__
        print(error)
    finally:
        remaining = lab.cleanup()
        if remaining:
            status = 1
        (output / "manifest.json").write_text(
            json.dumps(
                {
                    "action": args.action,
                    "host": platform.platform(),
                    "run_id": lab.run_id,
                    "finished_utc": datetime.now(UTC).isoformat(),
                    "exit": status,
                    "error": error,
                    "remaining_resources": remaining,
                    "events": lab.events,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"로컬 증거/로그: {output}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
