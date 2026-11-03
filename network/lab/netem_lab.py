"""승인된 netem 프로파일의 plan/build/probe/run. 기본 plan에는 부작용이 없다.

Why: 기존 실험의 기본 권한/판정을 유지하고 유한 실행·증거 회수·소유 정리를 재사용한다.
Constraints: 로컬 Linux Docker, 4조건×3회, 연결/GET 각 1회, 소유 internal bridge만 사용한다.
Side-effects: 명시적 build/probe/run만 자원/파일을 만들며 회수 실패 원본을 보존한다.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import math
import shutil
import sys
import time
import uuid
from pathlib import Path

import packet_lab as base
from netem_worker import BODY_SHA256, PROFILE, SCENARIOS
from packet_worker import FILE_BYTES, LOG_BYTES

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from netem_compare import ALL_FIELDS, compare  # noqa: E402
from roundtrip_timeline import fingerprint, strict_json  # noqa: E402

IMAGE = "cloudshield-network-netem-lab:local"
IMAGE_LABEL = "cloudshield.network.netem-lab"
WORKER = "/opt/lab/netem_worker.py"
LIMITS = {
    "profile": PROFILE,
    "repetitions": 3,
    "concurrency": 1,
    "connections": 1,
    "requests": 1,
    "body_bytes": 65536,
    "body_sha256": BODY_SHA256,
    "connect_seconds": 3,
    "io_seconds": 5,
    "client_seconds": 15,
    "capture_ready_seconds": 3,
    "capture_seconds": 20,
    "capture_packets": 1024,
    "pcap_bytes": FILE_BYTES,
    "tool_log_bytes": LOG_BYTES,
    "metadata_bytes": FILE_BYTES,
    "trial_bytes": 8 * FILE_BYTES,
    "suite_bytes": 128 * FILE_BYTES,
    "trial_seconds": 60,
    "cleanup_seconds": 15,
    "suite_work_seconds": 855,
    "suite_seconds": 960,
    "probe_seconds": 30,
    "build_seconds": 600,
    "terminate_seconds": 2,
    "kill_seconds": 1,
    "qdisc_packets": 128,
}
FILES = {
    "server": {"s-config.json", "s-app.json", "s-result.json", "s.pcap", "s.stdout", "s.stderr"},
    "client": {
        "config.json",
        "c-app.json",
        "c-result.json",
        "p.pcap",
        "p.stdout",
        "p.stderr",
        "q.pcap",
        "q.stdout",
        "q.stderr",
        "injection.json",
        "final.json",
        "body.bin",
    },
}
IMAGE_SOURCES = {
    "network/lab/netem_worker.py": WORKER,
    "network/lab/packet_worker.py": "/opt/lab/packet_worker.py",
    "network/tcpdump_capture.sh": "/opt/network/tcpdump_capture.sh",
    "network/lab/tcpdump.sh": "/usr/local/bin/tcpdump",
}


def evidence_json(raw):
    """공유 strict parser의 중복 키 검증 뒤 프로파일 수치 연산용 유한 float를 읽는다.

    Why: 앱 소요 시간과 tc 비율은 JSON number이며 공유 Decimal 객체를 직접 직렬화하지 않는다.
    Constraints: 원본 1MiB, NaN/Infinity/float overflow 거부. epoch 문자열의 정밀도는 유지한다.
    Side-effects: 순수 파싱이며 원본 증거는 변경하지 않는다.
    """
    if len(raw) > FILE_BYTES:
        raise ValueError("JSON 증거 1MiB 상한")
    strict_json(raw)

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("비유한 JSON 수치")
        return number

    return json.loads(raw, parse_float=finite)


def source_fingerprints():
    result = base.source_fingerprints()
    for name in (
        "network/lab/netem_lab.py",
        "network/lab/netem_worker.py",
        "network/netem_compare.py",
        "network/lab/Netem.Dockerfile",
        "network/lab/Netem.Dockerfile.dockerignore",
    ):
        path = base.ROOT / name
        if path.stat().st_size > FILE_BYTES:
            raise ValueError("프로파일 소스 상한")
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


class NetemLab(base.PacketLab):
    def __init__(self, output, scenario, *, seconds=60, seed_supported=False):
        if (
            scenario not in SCENARIOS
            or seconds not in (30, 60, 600)
            or type(seed_supported) is not bool
        ):
            raise ValueError("프로파일 시나리오/상한 오류")
        super().__init__(output, "normal")
        self.scenario = scenario
        self.run_id = "cs-netem-" + uuid.uuid4().hex
        self.deadline = time.monotonic() + seconds
        self.seed_supported = seed_supported
        self.probing = seconds == 30
        if self.probing:
            self.deadline = time.monotonic() + 15

    def capabilities(self, role):
        if self.probing:
            return ["NET_ADMIN"] if role == "client" else []
        return ["NET_RAW", "SETUID", "SETGID", "KILL"] + (["NET_ADMIN"] if role == "client" else [])

    def server_command(self):
        return ["sleep", "infinity"]

    def pair(self):
        self.preflight()
        item = json.loads(self.call("image", "inspect", IMAGE).stdout)[0]
        if item["Config"].get("Labels", {}).get(IMAGE_LABEL) != "netem-v1":
            raise ValueError("전용 이미지 아님; 명시적 build 필요")
        self.image_id = item["Id"]
        base.save(
            self.output / "image.json",
            {"id": self.image_id, "source_sha256": source_fingerprints()},
        )
        self.create_owned("network")
        server, client = self.create_owned("server"), self.create_owned("client")
        target, source = self.verify_pair(server, client)
        expected = {
            v: hashlib.sha256((base.ROOT / k).read_bytes()).hexdigest()
            for k, v in IMAGE_SOURCES.items()
        }
        actual = self.call("exec", client, "sha256sum", *IMAGE_SOURCES.values()).stdout
        if dict(reversed(line.split()) for line in actual.splitlines()) != expected:
            raise ValueError("실제 이미지/작업 소스 불일치; 명시적 build 필요")
        route = json.loads(self.call("exec", client, "ip", "-j", "route", "get", target).stdout)[0]
        if route.get("dev") != "eth0" or route.get("prefsrc") != source:
            raise ValueError("소유 인터페이스/경로 불일치")
        versions = {"image_sources": expected}
        for cmd in (
            ("uname", "-a"),
            ("tc", "-V"),
            ("tcpdump", "--version"),
            ("python3", "--version"),
            ("ethtool", "--version"),
        ):
            result = self.call("exec", client, *cmd)
            versions[cmd[0]] = result.stdout + result.stderr
        base.save(self.output / "versions.json", versions)
        return server, client, target, source

    def wait_marker(self, cid, marker, deadline):
        while True:
            value = self.call(
                "exec", cid, "cat", "/run/evidence/control/" + marker + ".json", check=False
            )
            if value.returncode == 0:
                if strict_json(value.stdout)["run_id"] != self.run_id:
                    raise ValueError("다른 실행의 worker barrier")
                return
            if time.monotonic() >= deadline:
                raise TimeoutError("worker barrier 상한")
            time.sleep(0.03)

    def preserve_role(self, cid, role):
        self.preserve(
            cid, worker_path=WORKER, quiescent_args=(role, self.run_id), allowed=FILES[role]
        )
        self.retained_containers.add(cid)
        for name in sorted(FILES[role]):
            path = self.output / name
            if path.is_file():
                if name.endswith("-app.json") and path.stat().st_size > LOG_BYTES:
                    raise ValueError("앱 로그 64KiB 초과")
                result = self.call("exec", cid, "sha256sum", "/run/evidence/" + name)
                fingerprint(path, result.stdout.split()[0])
        self.retained_containers.remove(cid)

    def experiment(self):
        server, client, target, source = self.pair()
        # 준비 단계 실패도 컨테이너의 부분 상태를 보존한다. 회수 완료 뒤에만 해제한다.
        self.retained_containers.add(client)
        prepare = [
            "exec",
            client,
            "python3",
            WORKER,
            "prepare",
            self.scenario,
            self.run_id,
            target,
            source,
        ]
        if self.seed_supported:
            prepare += ["--seed-supported"]
        self.call(*prepare, timeout=5)
        started = []
        try:
            started.append((server, "server"))
            self.call(
                "exec",
                "-d",
                server,
                "python3",
                WORKER,
                "server",
                self.scenario,
                self.run_id,
                target,
                source,
            )
            deadline = time.monotonic() + 3
            while not self.call("exec", server, "ss", "-H", "-lnt", "sport = :8080").stdout.strip():
                if time.monotonic() >= deadline:
                    raise TimeoutError("서버/캡처 준비 상한")
                time.sleep(0.02)
            started.append((client, "client"))
            self.call(
                "exec",
                "-d",
                client,
                "python3",
                WORKER,
                "client",
                self.scenario,
                self.run_id,
                target,
                source,
            )
            deadline = time.monotonic() + 6
            self.wait_marker(client, "connected", deadline)
            self.wait_marker(server, "accepted", deadline)
            self.call(
                "exec", client, "python3", WORKER, "arm", self.scenario, self.run_id, timeout=3
            )
            for cid, role in ((client, "client"), (server, "server")):
                self.call("exec", cid, "python3", WORKER, "wait", role, self.run_id, timeout=25)
        finally:
            failures = []
            for cid, role in reversed(started):
                try:
                    self.call("exec", cid, "python3", WORKER, "wait", role, self.run_id, timeout=25)
                    self.preserve_role(cid, role)
                except (Exception, KeyboardInterrupt) as exc:
                    failures.append(role + ": " + type(exc).__name__ + ": " + str(exc))
            if failures:
                raise RuntimeError("worker/회수 실패: " + "; ".join(failures))
        result = self.analyze()
        base.save(self.output / "analysis.json", result)
        return result

    def analyze(self):
        values = {
            name: evidence_json((self.output / name).read_bytes())
            for name in (
                "config.json",
                "c-app.json",
                "s-app.json",
                "c-result.json",
                "s-result.json",
                "injection.json",
                "final.json",
            )
        }
        tool = shutil.which("tshark") or "C:/Program Files/Wireshark/tshark.exe"
        version = base.bounded_command([tool, "--version"], timeout=3, env=self.env)
        base.save(self.output / "tshark-version.json", version)
        if version["code"] or version["reason"]:
            raise RuntimeError("TShark 버전 조회 실패")
        fields, follows, events = {}, {}, []
        for prefix in ("s", "p", "q"):
            args = [
                tool,
                "-n",
                "-2",
                "-r",
                str(self.output / (prefix + ".pcap")),
                "-o",
                "tcp.desegment_tcp_streams:TRUE",
                "-o",
                "tcp.reassemble_out_of_order:TRUE",
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
                args += ["-e", field]
            decoded = base.bounded_command(
                args,
                timeout=min(5, self.deadline - time.monotonic()),
                env=self.env,
                limit=FILE_BYTES,
            )
            fields[prefix] = decoded.pop("stdout")
            with (self.output / (prefix + ".csv")).open(
                "x", encoding="utf-8", newline=""
            ) as output:
                output.write(fields[prefix])
            events.append(decoded)
            if decoded["code"] or decoded["reason"]:
                raise RuntimeError("TShark 필드 추출 실패/상한")
            if prefix != "p":
                args = [
                    tool,
                    "-n",
                    "-q",
                    "-r",
                    str(self.output / (prefix + ".pcap")),
                    "-o",
                    "tcp.desegment_tcp_streams:TRUE",
                    "-o",
                    "tcp.reassemble_out_of_order:TRUE",
                    "-z",
                    "follow,tcp,raw,0",
                ]
                decoded = base.bounded_command(
                    args,
                    timeout=min(5, self.deadline - time.monotonic()),
                    env=self.env,
                    limit=FILE_BYTES,
                )
                follows[prefix] = decoded.pop("stdout")
                with (self.output / (prefix + "-follow.txt")).open(
                    "x", encoding="utf-8", newline=""
                ) as output:
                    output.write(follows[prefix])
                events.append(decoded)
                if decoded["code"] or decoded["reason"]:
                    raise RuntimeError("TShark 재조립 추출 실패/상한")
        base.save(self.output / "decoder.json", events)
        return compare(
            fields,
            follows,
            values["config.json"],
            values["c-app.json"],
            values["s-app.json"],
            values["c-result.json"],
            values["s-result.json"],
            values["injection.json"],
            values["final.json"],
            (self.output / "body.bin").read_bytes(),
        )


def probe(root):
    root.mkdir(parents=True, exist_ok=True)
    directory = base.create_run_directory(root)
    lab = NetemLab(directory / "probe", SCENARIOS[0], seconds=30)
    result = {"action": "probe", "passed": False, "tcp_connections": 0, "http_requests": 0}
    try:
        _, client, target, source = lab.pair()
        execution = lab.call(
            "exec",
            client,
            "python3",
            WORKER,
            "probe",
            "baseline",
            lab.run_id,
            target,
            source,
            timeout=8,
            check=False,
        )
        lab.preserve(
            client,
            worker_path=WORKER,
            quiescent_args=("client", lab.run_id),
            allowed={"config.json", "feature.json"},
        )
        feature = strict_json((lab.output / "feature.json").read_bytes())
        if (
            execution.returncode
            or feature["run_id"] != lab.run_id
            or not feature["complete"]
            or not feature["removed"]
        ):
            raise ValueError("기능 시험 증거/정리 불일치")
        result.update(passed=True, seed_supported=feature["seed_supported"])
    except (Exception, KeyboardInterrupt) as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        remaining = lab.cleanup()
        result["remaining_resources"] = remaining
        if remaining:
            result["passed"] = False
        base.save(lab.output / "commands.json", lab.events)
        base.evidence_manifest(lab.output, result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result


def suite(root):
    started = time.monotonic()
    feature = probe(root)
    if not feature["passed"]:
        return 1
    factory = functools.partial(NetemLab, seed_supported=feature["seed_supported"])
    return base.suite(
        root,
        lab_factory=factory,
        scenarios=SCENARIOS,
        limits=LIMITS,
        source_hashes=source_fingerprints,
        started_at=started,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", nargs="?", choices=("plan", "build", "probe", "run"), default="plan"
    )
    args = parser.parse_args(argv)
    if args.action == "plan":
        print(
            json.dumps(
                {"scenarios": SCENARIOS, "limits": LIMITS, "seed_supported": False},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    root = base.ROOT / "network/lab/runs/netem/experiments"
    if args.action == "probe":
        return 0 if probe(root)["passed"] else 1
    if args.action == "run":
        return suite(root)
    root.mkdir(parents=True, exist_ok=True)
    directory = base.create_run_directory(root)
    lab = NetemLab(directory / "build", SCENARIOS[0], seconds=600)
    result = {"action": "build", "passed": False}
    try:
        lab.preflight()
        lab.call(
            "build",
            "-t",
            IMAGE,
            "-f",
            str(base.ROOT / "network/lab/Netem.Dockerfile"),
            str(base.ROOT / "network"),
            timeout=max(0.001, lab.deadline - time.monotonic()),
        )
        result["passed"] = True
    except (Exception, KeyboardInterrupt) as exc:
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        base.save(lab.output / "commands.json", lab.events)
        base.evidence_manifest(lab.output, result)
    print(str(lab.output), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
