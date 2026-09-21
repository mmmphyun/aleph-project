"""소유한 로컬 Docker 서버에만 유한한 인증 실패를 만드는 명시적 실험 러너."""

import argparse
import ipaddress
import json
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime

from run import LABEL, ROOT, Lab

IMAGE = "cloudshield-network-hydra-lab:local"


def limits(candidates, seconds, tasks, port):
    if not 1 <= candidates <= 10 or not 3 <= seconds <= 55 or tasks != 1 or port != 2222:
        raise ValueError("후보 1~10, Hydra 3~55초(종료 유예 포함 60초 이내), 동시성 1, 포트 2222")


class HydraLab(Lab):
    def __init__(self, output, candidates=6, seconds=30):
        limits(candidates, seconds, 1, 2222)
        super().__init__(output)
        self.output.chmod(0o700)
        self.candidates = candidates
        self.seconds = seconds
        self.image_id = None

    def preserve(self, client):
        super().preserve(client)
        lines = (self.output / "tcpdump-read.txt").read_text(encoding="utf-8").splitlines()
        self.events.append({"pcap_packet_count": len(lines)})

    def create(self, role):
        if role not in ("server", "client"):
            raise ValueError("컨테이너 역할 오류")
        caps = (
            ["SETUID", "SETGID", "SYS_CHROOT", "CHOWN", "FOWNER"]
            if role == "server"
            else ["NET_RAW", "SETUID", "SETGID", "KILL"]
        )
        args = [
            "create",
            "--name",
            self.run_id + "-" + role,
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
            "--tmpfs",
            "/run/private:rw,noexec,nosuid,mode=0700",
            "--log-driver",
            "local",
        ]
        for cap in caps:
            args += ["--cap-add", cap]
        args += [self.image_id]
        args += ["bash", "/opt/lab/hydra_server.sh"] if role == "server" else ["sleep", "infinity"]
        cid = self.call(*args).stdout.strip()
        self.containers.append(cid)
        self.call("start", cid)
        return cid

    def verify_target(self, server, client):
        # 사설 IP 여부는 허가 근거가 아니다. 이번 create 결과와 엔진의 실제 격리를 대조한다.
        net = json.loads(self.call("network", "inspect", self.network).stdout)[0]
        if (
            net["Id"] != self.network
            or not net["Internal"]
            or net["Driver"] != "bridge"
            or net.get("Labels", {}).get(LABEL) != self.run_id
            or set(net.get("Containers", {})) != {server, client}
        ):
            raise RuntimeError("소유 internal 네트워크 불일치")
        addresses = []
        for cid in (server, client):
            item = json.loads(self.call("inspect", cid).stdout)[0]
            host = item["HostConfig"]
            networks = list(item["NetworkSettings"]["Networks"].values())
            if (
                cid not in self.containers
                or item["Id"] != cid
                or item["Config"].get("Labels", {}).get(LABEL) != self.run_id
                or item["Image"] != self.image_id
                or not item["State"]["Running"]
                or len(networks) != 1
                or networks[0]["NetworkID"] != self.network
                or host.get("PortBindings")
                or host.get("PublishAllPorts")
                or host.get("Privileged")
                or host.get("NetworkMode") in ("host", "none")
                or host.get("Binds")
                or any(m["Type"] != "tmpfs" for m in item.get("Mounts", []))
            ):
                raise RuntimeError("컨테이너 소유권/격리 불일치")
            addresses.append(str(ipaddress.IPv4Address(networks[0]["IPAddress"])))
        config = self.call(
            "exec", server, "/usr/sbin/sshd", "-T", "-f", "/opt/lab/hydra_sshd_config"
        ).stdout
        required = {
            "port 2222",
            "permitrootlogin no",
            "allowusers hydralab",
            "passwordauthentication yes",
            "authenticationmethods password",
        }
        if not required <= set(config.splitlines()):
            raise RuntimeError("실험 SSH 포트/인증 설정 불일치")
        return addresses

    def server_evidence(self, server, client_ip):
        logs = self.call("logs", "--timestamps", server, check=False)
        if logs.returncode:
            raise RuntimeError("실제 서버 로그 확보 실패")
        text = logs.stdout + logs.stderr
        (self.output / "sshd.log").write_text(text, encoding="utf-8")
        failed = re.findall(
            r"Failed password for hydralab from " + re.escape(client_ip) + r" port (\d+) ssh2", text
        )
        accepted = re.findall(r"Accepted \S+ for ", text)
        self.events.append(
            {
                "server_failed_password_count": len(failed),
                "server_failure_source_ports": failed,
                "server_accepted_count": len(accepted),
                "log_sink": "sshd stderr",
            }
        )
        return len(failed), len(accepted)

    def capture_hydra(self, server, client, target, client_ip, interface):
        args = [
            "docker",
            "--context",
            self.context,
            "exec",
            client,
            "bash",
            "/opt/network/tcpdump_capture.sh",
            target,
            "2222",
            interface,
            "/tmp/capture.pcap",
            str(self.seconds + 3),
            "5000",
        ]
        self.events.append({"capture_command": args})
        proc = None
        with (
            (self.output / "capture.stdout").open("xb") as out,
            (self.output / "capture.stderr").open("xb") as err,
        ):
            try:
                proc = subprocess.Popen(args, stdout=out, stderr=err, env=self.env)
                for _ in range(50):
                    if proc.poll() is not None:
                        raise RuntimeError("캡처 준비 전 종료")
                    if "listening on " in (self.output / "capture.stderr").read_text(
                        errors="replace"
                    ):
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("캡처 준비 시간 초과")
                # 시작 직전에 재검사하며 사용자 제공 호스트로 대체하는 경로가 없다.
                if self.verify_target(server, client) != [target, client_ip]:
                    raise RuntimeError("실행 직전 대상 변경")
                self.events.append({"capture_ready_utc": datetime.now(UTC).isoformat()})
                spec = {
                    "target": target,
                    "port": 2222,
                    "tasks": 1,
                    "candidates": self.candidates,
                    "seconds": self.seconds,
                    "run_id": self.run_id,
                }
                result = self.call(
                    "exec",
                    "-i",
                    client,
                    "timeout",
                    "-k",
                    "1",
                    str(self.seconds + 2),
                    "python3",
                    "/opt/lab/hydra_worker.py",
                    data=json.dumps(spec),
                    timeout=self.seconds + 5,
                    check=False,
                )
                hydra = json.loads(result.stdout)
                self.events.append({"hydra": hydra, "worker_exit": result.returncode})
                code = proc.wait(timeout=10)
                self.events.append({"capture_exit": code})
                failures, accepted = self.server_evidence(server, client_ip)
                if accepted or hydra["state"] == "unexpected_success":
                    raise RuntimeError("예상하지 못한 인증 성공: 실험 중단, 서버 로그 확인 필요")
                if code not in (0, 124):
                    raise RuntimeError("캡처 실행 오류")
                if hydra["state"] != "exhausted_without_success" or not failures:
                    raise RuntimeError("인증 실패 재현 미확인: Hydra 상태와 서버 로그 확인")
            finally:
                # 자체 타이머의 flush를 기다린다. CLI 강제 종료 시 보존은 미보장이다.
                if proc is not None and proc.poll() is None:
                    try:
                        proc.wait(timeout=self.seconds + 6)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                        proc.wait(timeout=5)
                if proc is not None:
                    self.events.append({"capture_final_exit": proc.returncode})
                log = (self.output / "capture.stderr").read_text(errors="replace")
                drops = re.search(r"(\d+) packets dropped by kernel", log)
                self.events.append({"kernel_dropped_packets": int(drops[1]) if drops else None})

    def experiment(self):
        image = json.loads(self.call("image", "inspect", IMAGE).stdout)[0]
        if image["Config"].get("Labels", {}).get(LABEL) != "hydra-fail-v1":
            raise RuntimeError("Hydra 전용 이미지 불일치")
        self.image_id = image["Id"]
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
        server = self.create("server")
        client = self.create("client")
        capture_attempted = False
        client_ip = None
        try:
            self.wait_listener(server)
            target, client_ip = self.verify_target(server, client)
            route = json.loads(
                self.call("exec", client, "ip", "-j", "route", "get", target).stdout
            )[0]
            interface = route["dev"]
            if route.get("prefsrc") != client_ip or not re.fullmatch(
                r"[a-zA-Z0-9][\w.:-]{0,14}", interface
            ):
                raise RuntimeError("캡처 경로/인터페이스 불일치")
            for cmd in (
                ["uname", "-a"],
                ["cat", "/etc/os-release"],
                ["ssh", "-V"],
                ["tcpdump", "--version"],
                ["date", "--iso-8601=ns"],
                ["date", "-u", "--iso-8601=ns"],
            ):
                self.call("exec", client, *cmd)
            self.events.append(
                {
                    "server_ip": target,
                    "client_ip": client_ip,
                    "port": 2222,
                    "interface": interface,
                    "image_id": self.image_id,
                    "host_local_time": datetime.now().astimezone().isoformat(),
                }
            )
            capture_attempted = True
            self.capture_hydra(server, client, target, client_ip, interface)
        finally:
            primary = sys.exception()
            errors = []
            actions = []
            if client_ip:
                actions.append(lambda: self.server_evidence(server, client_ip))
            if capture_attempted:
                actions.append(lambda: self.preserve(client))
            for action in actions:
                try:
                    action()
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    errors.append(str(exc))
            # 원본 복사 실패로 컨테이너를 남기더라도 후보/복구 파일 tmpfs는 지운다.
            scrub = self.call(
                "exec", client, "find", "/run/private", "-mindepth", "1", "-delete", check=False
            )
            self.events.append({"private_cleanup_exit": scrub.returncode, "archive_errors": errors})
            if errors and primary is None:
                raise RuntimeError("; ".join(errors))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=["plan", "build", "run"], default="plan")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--candidates", type=int, default=6)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--tasks", type=int, default=1)
    parser.add_argument("--port", type=int, default=2222)
    args = parser.parse_args(argv)
    try:
        limits(args.candidates, args.seconds, args.tasks, args.port)
    except ValueError as exc:
        parser.error(str(exc))
    if args.action == "plan" or (args.action == "run" and not args.execute):
        print(
            f"DRY RUN: 로컬 Docker 전용 서버, 2222, 후보 {args.candidates}, 동시성 1, "
            f"Hydra {args.seconds}초; 실제 실행은 run --execute"
        )
        return 0
    output = (
        ROOT
        / "network/lab/runs"
        / (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-hydra-") + uuid.uuid4().hex[:8])
    )
    lab = HydraLab(output, args.candidates, args.seconds)
    status, error = 1, None
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        if not shutil.which("docker"):
            raise RuntimeError("Docker CLI 없음: 설치 경로 또는 별도 설치 승인 필요")
        lab.preflight()
        if args.action == "build":
            lab.call(
                "build",
                "-t",
                IMAGE,
                "-f",
                str(ROOT / "network/lab/Hydra.Dockerfile"),
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
