"""기본 plan은 부작용이 없다. build/run에서만 전용 Docker 자원과 증거를 생성한다.

Why: 기존 SSH Lab의 엔진 제한·소유권과 캡처 패턴을 계승하되 AWS 경로는 호출하지 않는다.
Constraints: 4종×3회, 동시성 1, 작업 45초/정리 15초, 회차 4MiB/묶음 64MiB.
Side-effects: 소유 자원만 정리한다. 확보 실패 원본은 보존하고 모든 실패를 비정상 종료한다.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from packet_worker import FILE_BYTES, LOG_BYTES, PORT, SCENARIOS
from run import LABEL, ROOT, Lab

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo_attack_runner import create_run_directory  # noqa: E402
from packet_scenario_compare import ALL_FIELDS, compare  # noqa: E402
from roundtrip_timeline import fingerprint, strict_json  # noqa: E402

IMAGE = "cloudshield-network-packet-lab:local"
IMAGE_LABEL = "cloudshield.network.packet-lab"
LIMITS = {
    "repetitions": 3,
    "concurrency": 1,
    "connection_attempts_per_trial": 1,
    "request_limit": 1,
    "connect_seconds": 4,
    "request_seconds": 5,
    "client_watchdog_seconds": 6,
    "capture_ready_seconds": 3,
    "capture_seconds": 8,
    "capture_packets": 256,
    "pcap_bytes": FILE_BYTES,
    "tool_log_bytes": LOG_BYTES,
    "metadata_bytes": FILE_BYTES,
    "trial_bytes": 4 * FILE_BYTES,
    "suite_bytes": 64 * FILE_BYTES,
    "trial_seconds": 45,
    "cleanup_seconds": 15,
    "suite_seconds": 780,
    "build_seconds": 600,
    "terminate_seconds": 2,
    "kill_seconds": 1,
}


def save(path, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    if len(raw) > FILE_BYTES:
        raise ValueError("메타데이터 1MiB 상한 초과")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def terminate(process):
    """Windows 호스트는 소유 Popen만 종료한다. 컨테이너 내부 자식은 별도 정리한다."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


def bounded_command(argv, *, timeout, env, limit=LOG_BYTES, binary=False):
    """출력을 파일로 감시하고 초과·중단을 구별한다. 부분 출력은 오류 표시와 함께 반환한다."""
    if not 0 < timeout <= 600 or not 0 < limit <= FILE_BYTES:
        raise ValueError("명령 시간/출력 상한 오류")
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err, env=env)
        reason = None
        try:
            deadline = time.monotonic() + timeout
            while True:
                if any(os.fstat(f.fileno()).st_size > limit for f in (out, err)):
                    reason = "output_limit"
                    break
                if process.poll() is not None:
                    break
                if time.monotonic() >= deadline:
                    reason = "tool_timeout"
                    break
                time.sleep(0.02)
        except KeyboardInterrupt:
            reason = "interrupted"
        finally:
            terminate(process)
        if any(os.fstat(f.fileno()).st_size > limit for f in (out, err)):
            reason = reason or "output_limit"
        values = []
        for index, handle in enumerate((out, err)):
            handle.seek(0)
            raw = handle.read(limit)
            values.append(raw if binary and index == 0 else raw.decode("utf-8", errors="replace"))
        return {
            "command": argv,
            "code": process.returncode if reason is None else 125,
            "reason": reason,
            "stdout": values[0],
            "stderr": values[1],
            "partial_output": reason is not None,
        }


def evidence_manifest(directory, metadata, *, limit=4 * FILE_BYTES):
    """기존 청크 해시 검증을 재사용한다. manifest 자체 해시는 별도 파일에 기록한다."""
    files, size = {}, 0
    for path in sorted(directory.iterdir()):
        if path.is_dir() or path.is_symlink() or path.name in ("manifest.json", "manifest.sha256"):
            raise ValueError("예상하지 못한 증거 경로/기존 manifest")
        if path.stat().st_size > FILE_BYTES:
            raise ValueError("증거 파일 용량 초과")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        info, _ = fingerprint(path, digest.hexdigest())
        if info["bytes"] > FILE_BYTES or len(files) >= 32:
            raise ValueError("증거 파일 용량/개수 초과")
        files[path.name] = info
        size += info["bytes"]
    if size > limit - 2 * FILE_BYTES:
        # manifest 공간까지 선예약한다. 실패 시 기존 원본은 삭제하지 않는다.
        raise ValueError("증거 묶음 용량 초과")
    save(directory / "manifest.json", {**metadata, "files": files})
    raw = (directory / "manifest.json").read_bytes()
    with (directory / "manifest.sha256").open("x", encoding="ascii") as stream:
        stream.write(hashlib.sha256(raw).hexdigest() + "  manifest.json\n")
    return files


class PacketLab(Lab):
    def __init__(self, output, scenario, *, seconds=45):
        if scenario not in SCENARIOS or seconds not in (45, 600):
            raise ValueError("고정 시나리오/상한 오류")
        super().__init__(output)
        self.run_id = "cs-packet-" + uuid.uuid4().hex
        self.scenario = scenario
        self.deadline = time.monotonic() + seconds
        self.image_id = None
        self.pending = []

    def call(self, *args, check=True, timeout=5):
        remaining = self.deadline - time.monotonic()
        if remaining <= 3:
            raise TimeoutError("회차 전체 시간 상한 초과")
        argv = ["docker"] + (["--context", self.context] if self.context else []) + list(args)
        event = bounded_command(argv, timeout=min(timeout, remaining - 3), env=self.env)
        self.events.append(event)
        if len(json.dumps(self.events).encode()) > 800000:
            raise ValueError("명령 기록 상한 초과")
        if event["reason"] == "interrupted":
            raise KeyboardInterrupt("소유 명령 중단")
        result = subprocess.CompletedProcess(argv, event["code"], event["stdout"], event["stderr"])
        if event["reason"] or (check and result.returncode):
            raise RuntimeError(f"도구 실패: {args[0]}: {event['reason'] or result.returncode}")
        return result

    def create_owned(self, role):
        if role not in ("network", "server", "client"):
            raise ValueError("소유 자원 역할 오류")
        name = self.run_id + "-" + role
        if role == "network":
            args = [
                "network",
                "create",
                "--internal",
                "--driver",
                "bridge",
                "--label",
                f"{LABEL}={self.run_id}",
                name,
            ]
        else:
            caps = (
                ["NET_RAW", "SETUID", "SETGID", "KILL"]
                if role == "client"
                else (["NET_ADMIN"] if self.scenario in ("drop", "rst") else [])
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
                "--cpus",
                "1",
                "--read-only",
                "--tmpfs",
                "/run/evidence:rw,noexec,nosuid,size=4m,mode=0700",
                "--log-driver",
                "local",
                "--log-opt",
                "max-size=64k",
                "--log-opt",
                "max-file=1",
                "--log-opt",
                "compress=false",
                "--env",
                "PYTHONDONTWRITEBYTECODE=1",
            ]
            for cap in caps:
                args += ["--cap-add", cap]
            args += [self.image_id]
            args += (
                [
                    "python3",
                    "/opt/lab/packet_worker.py",
                    "serve",
                    "403" if self.scenario == "http403" else "200",
                ]
                if role == "server"
                else ["sleep", "infinity"]
            )
        # CLI timeout은 create가 서버에 도달했는지 알 수 없다. 정확한 이름+label로만 회수한다.
        self.pending.append((role, name))
        identity = self.call(*args).stdout.strip()
        if not re.fullmatch(r"[a-f0-9]{64}", identity):
            raise ValueError("Docker 생성 ID 오류")
        if role == "network":
            self.network = identity
        else:
            self.containers.append(identity)
        self.pending.remove((role, name))
        if role != "network":
            self.call("start", identity)
        return identity

    def verify_pair(self, server, client):
        net = json.loads(self.call("network", "inspect", self.network).stdout)[0]
        if (
            net["Id"] != self.network
            or not net["Internal"]
            or net["Driver"] != "bridge"
            or net.get("Labels", {}).get(LABEL) != self.run_id
            or set(net.get("Containers", {})) != {server, client}
        ):
            raise ValueError("전용 네트워크 소유권 불일치")
        addresses = []
        for cid in (server, client):
            item = json.loads(self.call("inspect", cid).stdout)[0]
            host = item["HostConfig"]
            nets = list(item["NetworkSettings"]["Networks"].values())
            expected_caps = (
                ["NET_RAW", "SETUID", "SETGID", "KILL"]
                if cid == client
                else (["NET_ADMIN"] if self.scenario in ("drop", "rst") else [])
            )
            if (
                item["Id"] != cid
                or cid not in self.containers
                or item["Config"].get("Labels", {}).get(LABEL) != self.run_id
                or item["Image"] != self.image_id
                or not item["State"]["Running"]
                or len(nets) != 1
                or nets[0]["NetworkID"] != self.network
                or host.get("PortBindings")
                or host.get("PublishAllPorts")
                or host.get("Privileged")
                or host.get("Binds")
                or host.get("NetworkMode") != self.network
                or not host.get("ReadonlyRootfs")
                or set(host.get("CapDrop") or []) != {"ALL"}
                or "no-new-privileges:true" not in (host.get("SecurityOpt") or [])
                or {cap.removeprefix("CAP_") for cap in (host.get("CapAdd") or [])}
                != set(expected_caps)
                or any(m["Type"] != "tmpfs" for m in item.get("Mounts", []))
            ):
                raise ValueError("소유 컨테이너 격리 불일치")
            addresses.append(nets[0]["IPAddress"])
        return addresses

    def firewall(self, server, client_ip, *, install=False):
        if self.scenario not in ("drop", "rst"):
            return {"rule_verified": True, "rule_packets": 0}
        rule = ["-s", client_ip + "/32", "-p", "tcp", "--dport", str(PORT), "-j"]
        rule += ["DROP"] if self.scenario == "drop" else ["REJECT", "--reject-with", "tcp-reset"]
        if install:
            self.call("exec", server, "iptables", "-w", "1", "-A", "INPUT", *rule)
        self.call("exec", server, "iptables", "-w", "1", "-C", "INPUT", *rule)
        saved = self.call("exec", server, "iptables-save", "-c").stdout
        save(
            self.output / ("firewall-before.json" if install else "firewall-after.json"),
            {"command_rule": rule, "iptables_save": saved},
        )
        matching = [
            line
            for line in saved.splitlines()
            if "-A INPUT " in line and client_ip + "/32" in line and "--dport 8080" in line
        ]
        if len(matching) != 1:
            raise ValueError("방화벽 규칙 증거 불일치")
        counter = re.match(r"\[(\d+):\d+\] ", matching[0])
        if not counter:
            raise ValueError("방화벽 카운터 없음")
        return {"rule_verified": True, "rule_packets": int(counter[1])}

    def preserve(self, client):
        # 복사 실패 시 원본 tmpfs를 가진 컨테이너와 네트워크를 보존한다.
        self.retained_containers.add(client)
        self.call("exec", client, "python3", "/opt/lab/packet_worker.py", "quiescent", self.run_id)
        listing = self.call(
            "exec",
            client,
            "find",
            "/run/evidence",
            "-maxdepth",
            "1",
            "-type",
            "f",
            "-printf",
            "%f %s\n",
        ).stdout
        entries = listing.splitlines()
        if len(entries) > 12:
            raise ValueError("컨테이너 증거 개수 초과")
        allowed = {
            "config.json",
            "worker-result.json",
            "capture.pcap",
            "capture.stdout",
            "capture.stderr",
            "curl.stdout",
            "curl.stderr",
            "headers.txt",
            "body.txt",
        }
        for line in entries:
            name, size = line.rsplit(" ", 1)
            bound = LOG_BYTES if name.endswith((".stdout", ".stderr")) else FILE_BYTES
            if name not in allowed or not size.isdigit() or int(size) > bound:
                raise ValueError("컨테이너 증거 경로/용량 오류")
            destination = self.output / name
            if destination.exists():
                raise FileExistsError("기존 증거 덮어쓰기 금지")
            checksum = self.call("exec", client, "sha256sum", "/run/evidence/" + name)
            expected = checksum.stdout.split()[0]
            # Docker archive API는 이 엔진의 tmpfs 내용을 내보내지 않는다. exec의 바이너리
            # 스트림을 상한 내로 읽고, cat 전 원본 해시와 저장 후 해시를 대조한다.
            argv = [
                "docker",
                "--context",
                self.context,
                "exec",
                client,
                "cat",
                "/run/evidence/" + name,
            ]
            copied = bounded_command(
                argv,
                timeout=min(3, self.deadline - time.monotonic()),
                env=self.env,
                limit=bound,
                binary=True,
            )
            raw = copied.pop("stdout")
            self.events.append(
                {
                    **copied,
                    "stdout_bytes": len(raw),
                    "stdout_sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
            if copied["code"] or copied["reason"] or len(raw) != int(size):
                raise RuntimeError("증거 바이너리 전송 실패; 원본 보존")
            with destination.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            fingerprint(destination, expected)
        self.retained_containers.remove(client)

    def experiment(self):
        self.preflight()
        image = json.loads(self.call("image", "inspect", IMAGE).stdout)[0]
        if image["Config"].get("Labels", {}).get(IMAGE_LABEL) != "packet-v1":
            raise ValueError("전용 이미지 아님; 명시적 build 필요")
        self.image_id = image["Id"]
        save(
            self.output / "image.json",
            {
                "id": self.image_id,
                "tags": image.get("RepoTags"),
                "layers": image.get("RootFS"),
                "size": image["Size"],
            },
        )
        self.create_owned("network")
        server, client = self.create_owned("server"), self.create_owned("client")
        target, source = self.verify_pair(server, client)
        # LISTEN과 경로 조회는 TCP 요청을 만들지 않아 신규 연결 수를 오염시키지 않는다.
        ready = time.monotonic() + 3
        while not self.call("exec", server, "ss", "-H", "-lnt", "sport = :8080").stdout.strip():
            if time.monotonic() >= ready:
                raise TimeoutError("HTTP 서버 준비 실패")
            time.sleep(0.05)
        route = json.loads(self.call("exec", client, "ip", "-j", "route", "get", target).stdout)[0]
        if route.get("dev") != "eth0" or route.get("prefsrc") != source:
            raise ValueError("단일 캡처 인터페이스/주소 불일치")
        self.firewall(server, source, install=True)
        versions = {}
        for cmd in (
            ("uname", "-a"),
            ("curl", "--version"),
            ("tcpdump", "--version"),
            ("python3", "--version"),
            ("iptables", "--version"),
        ):
            value = self.call("exec", client, *cmd)
            versions[cmd[0]] = value.stdout + value.stderr
        save(self.output / "versions.json", versions)
        capture_attempted = False
        try:
            capture_attempted = True
            self.call(
                "exec",
                client,
                "timeout",
                "--signal=TERM",
                "--kill-after=3",
                "13",
                "python3",
                "/opt/lab/packet_worker.py",
                "trial",
                self.scenario,
                target,
                source,
                self.run_id,
                check=False,
                timeout=17,
            )
        finally:
            if capture_attempted:
                self.preserve(client)
        config = strict_json((self.output / "config.json").read_bytes())
        config.update(self.firewall(server, source))
        save(self.output / "scenario.json", config)
        worker = strict_json((self.output / "worker-result.json").read_bytes())
        tool = shutil.which("tshark") or "C:/Program Files/Wireshark/tshark.exe"
        tool_version = bounded_command([tool, "--version"], timeout=3, env=self.env)
        if tool_version["code"]:
            raise RuntimeError("TShark 버전 조회 실패")
        save(self.output / "tshark-version.json", tool_version)
        argv = [
            tool,
            "-n",
            "-r",
            str(self.output / "capture.pcap"),
            "-d",
            "tcp.port==8080,http",
            "-Y",
            "tcp",
            "-T",
            "fields",
            "-E",
            "header=y",
            "-E",
            "separator=,",
            "-E",
            "quote=d",
            "-E",
            "occurrence=f",
        ]
        for field in ALL_FIELDS:
            argv += ["-e", field]
        remaining = min(5, self.deadline - time.monotonic())
        decoded = bounded_command(argv, timeout=remaining, env=self.env, limit=FILE_BYTES)
        with (self.output / "packets.csv").open("x", encoding="utf-8", newline="") as stream:
            stream.write(decoded.pop("stdout"))
        save(self.output / "decoder.json", decoded)
        if decoded["code"]:
            raise RuntimeError("TShark 디코딩 실패")
        result = compare((self.output / "packets.csv").read_text(encoding="utf-8"), worker, config)
        save(self.output / "analysis.json", result)
        return result

    def cleanup(self):
        self.deadline = time.monotonic() + 15
        failures = []
        for role, name in self.pending:
            try:
                args = ["network", "inspect", name] if role == "network" else ["inspect", name]
                found = self.call(*args, check=False, timeout=2)
                if found.returncode:
                    failures.append(name + ": creation outcome unknown")
                    continue
                item = json.loads(found.stdout)[0]
                labels = (
                    item.get("Labels", {})
                    if role == "network"
                    else item["Config"].get("Labels", {})
                )
                if labels.get(LABEL) != self.run_id:
                    failures.append(name + ": ownership mismatch")
                elif role == "network":
                    self.network = item["Id"]
                else:
                    self.containers.append(item["Id"])
            except (Exception, KeyboardInterrupt) as exc:
                failures.append(name + ": " + type(exc).__name__)
        for cid in reversed(self.containers):
            if cid in self.retained_containers:
                failures.append(cid + ": original evidence retained")
                continue
            try:
                item = json.loads(self.call("inspect", cid, timeout=2).stdout)[0]
                if item["Id"] != cid or item["Config"].get("Labels", {}).get(LABEL) != self.run_id:
                    raise ValueError("정리 소유권 불일치")
                self.call("rm", "-f", cid, timeout=2)
            except (Exception, KeyboardInterrupt) as exc:
                failures.append(cid + ": " + type(exc).__name__)
        if self.network:
            try:
                net = json.loads(self.call("network", "inspect", self.network, timeout=2).stdout)[0]
                if (
                    net["Id"] != self.network
                    or net.get("Labels", {}).get(LABEL) != self.run_id
                    or net.get("Containers")
                ):
                    raise ValueError("정리 네트워크 소유권/잔여 컨테이너 불일치")
                self.call("network", "rm", self.network, timeout=2)
            except (Exception, KeyboardInterrupt) as exc:
                failures.append(self.network + ": " + type(exc).__name__)
        return failures


def suite(root):
    root.mkdir(parents=True, exist_ok=True)
    directory = create_run_directory(root)
    started = time.monotonic()
    trials = []
    save(
        directory / "plan.json",
        {
            "limits": LIMITS,
            "scenarios": SCENARIOS,
            "host": platform.platform(),
            "source_commit": source_commit(),
            "source_sha256": source_fingerprints(),
        },
    )
    interrupted = False
    for mode in SCENARIOS:
        for repetition in range(1, 4):
            if interrupted or time.monotonic() - started >= 720:
                trials.append(
                    {
                        "scenario": mode,
                        "repetition": repetition,
                        "passed": False,
                        "error": "not_started: interrupt/suite_deadline",
                    }
                )
                continue
            lab = PacketLab(directory / f"{mode}-{repetition}", mode)
            result = {
                "scenario": mode,
                "repetition": repetition,
                "run_id": lab.run_id,
                "passed": False,
                "error": None,
            }
            try:
                analysis = lab.experiment()
                result["passed"] = analysis["passed"]
                result["reasons"] = analysis["reasons"]
            except (Exception, KeyboardInterrupt) as exc:
                result["error"] = type(exc).__name__ + ": " + str(exc)
                interrupted = isinstance(exc, KeyboardInterrupt)
            finally:
                remaining = lab.cleanup()
                result["remaining_resources"] = remaining
                if remaining:
                    result["passed"] = False
                    interrupted = True
                try:
                    save(lab.output / "commands.json", lab.events)
                    files = evidence_manifest(lab.output, {"result": result, "limits": LIMITS})
                    result["manifest_sha256"] = hashlib.sha256(
                        (lab.output / "manifest.json").read_bytes()
                    ).hexdigest()
                    result["evidence_bytes"] = (
                        sum(info["bytes"] for info in files.values())
                        + (lab.output / "manifest.json").stat().st_size
                        + (lab.output / "manifest.sha256").stat().st_size
                    )
                except (Exception, KeyboardInterrupt) as exc:
                    result["passed"] = False
                    result["archive_error"] = type(exc).__name__ + ": " + str(exc)
                    interrupted = True
                trials.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
    summary = {
        "trials": trials,
        "complete": len(trials) == 12 and all(t["passed"] for t in trials),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "limits": LIMITS,
        "plan_sha256": hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest(),
    }
    if sum(t.get("evidence_bytes", 0) for t in trials) + 2 * FILE_BYTES > LIMITS["suite_bytes"]:
        raise ValueError("실행 묶음 용량 상한 초과; 원본 보존")
    save(directory / "summary.json", summary)
    with (directory / "summary.sha256").open("x", encoding="ascii") as stream:
        stream.write(
            hashlib.sha256((directory / "summary.json").read_bytes()).hexdigest()
            + "  summary.json\n"
        )
    print(str(directory), flush=True)
    return 0 if summary["complete"] else 1


def source_commit():
    result = bounded_command(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], timeout=2, env=os.environ.copy()
    )
    if result["code"]:
        raise RuntimeError("소스 커밋 확인 실패")
    return result["stdout"].strip()


def source_fingerprints():
    """커밋 전 실험도 실제 작업 트리 바이트와 연결한다. 자격증명 경로는 읽지 않는다."""
    files = (
        "network/lab/packet_lab.py",
        "network/lab/packet_worker.py",
        "network/lab/Packet.Dockerfile",
        "network/lab/Packet.Dockerfile.dockerignore",
        "network/packet_scenario_compare.py",
        "network/tcpdump_capture.sh",
        "network/lab/tcpdump.sh",
        "network/waf_packet_timeline.py",
        "network/sg_connection_timeline.py",
        "network/roundtrip_timeline.py",
        "network/demo_attack_runner.py",
    )
    result = {}
    for name in files:
        path = ROOT / name
        if path.stat().st_size > FILE_BYTES:
            raise ValueError("소스 파일 상한 초과")
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("plan", "build", "run"), default="plan")
    parser.add_argument("--output-root", type=Path, default=ROOT / "network/lab/runs")
    args = parser.parse_args(argv)
    if args.action == "plan":
        print(json.dumps({"scenarios": SCENARIOS, "limits": LIMITS}, ensure_ascii=False, indent=2))
        return 0
    if args.output_root.resolve() != (ROOT / "network/lab/runs").resolve():
        parser.error("증거는 network/lab/runs 아래에만 저장합니다")
    if args.action == "run":
        return suite(args.output_root)
    args.output_root.mkdir(parents=True, exist_ok=True)
    directory = create_run_directory(args.output_root)
    lab = PacketLab(directory / "build", "normal", seconds=600)
    result = {"action": "build", "passed": False}
    try:
        lab.preflight()
        lab.call(
            "build",
            "-t",
            IMAGE,
            "-f",
            str(ROOT / "network/lab/Packet.Dockerfile"),
            str(ROOT / "network"),
            timeout=max(0.001, lab.deadline - time.monotonic()),
        )
        result["passed"] = True
    except (Exception, KeyboardInterrupt) as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        save(lab.output / "commands.json", lab.events)
        evidence_manifest(lab.output, result)
    print(str(lab.output), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
