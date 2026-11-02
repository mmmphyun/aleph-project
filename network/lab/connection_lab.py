"""기본 plan에는 부작용이 없다. 승인된 4종×3회 실험만 명시적으로 실행한다.

Why: 기존 단일 요청 실험을 보존하면서 증거 회수·해시·소유권·상한 실행을 재사용한다.
Constraints: 로컬 Linux Docker, 작업 45초/정리 15초, 소유 internal bridge만 허용한다.
Side-effects: build/run만 파일·자원을 만들며 수집 실패 원본과 잔여 자원 ID를 보존한다.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import time
import uuid
from pathlib import Path

import packet_lab as base
from connection_worker import CAPTURE_SECONDS, PACKETS, PROFILE, SCENARIOS
from packet_worker import FILE_BYTES, LOG_BYTES, PORT

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from connection_compare import compare  # noqa: E402
from demo_attack_runner import create_run_directory  # noqa: E402
from roundtrip_timeline import fingerprint, strict_json  # noqa: E402

IMAGE = "cloudshield-network-connection-lab:local"
IMAGE_LABEL = "cloudshield.network.connection-lab"
LIMITS = {
    "profile": PROFILE,
    "repetitions": 3,
    "concurrency": 1,
    "http_reuse": {"connections": 1, "requests": 3},
    "http_close": {"connections": 2, "requests": 3},
    "half_close": {"connections": 1, "messages_each_direction": 1, "message_bytes": 256},
    "established_rst": {"connections": 1, "messages": 1, "message_bytes": 256},
    "connect_seconds": 3,
    "io_seconds": 2,
    "client_seconds": 10,
    "capture_ready_seconds": 3,
    "capture_seconds": CAPTURE_SECONDS,
    "capture_packets": PACKETS,
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
CLIENT_FILES = {
    "config.json",
    "client.json",
    "worker-result.json",
    "capture.pcap",
    "capture.stdout",
    "capture.stderr",
}
SERVER_FILES = {"server-config.json", "server.json", "server-result.json"}
IMAGE_SOURCES = {
    "network/lab/connection_worker.py": "/opt/lab/connection_worker.py",
    "network/lab/packet_worker.py": "/opt/lab/packet_worker.py",
    "network/tcpdump_capture.sh": "/opt/network/tcpdump_capture.sh",
    "network/lab/tcpdump.sh": "/usr/local/bin/tcpdump",
}


def source_fingerprints():
    result = base.source_fingerprints()
    for name in (
        "network/lab/connection_lab.py",
        "network/lab/connection_worker.py",
        "network/lab/Connection.Dockerfile",
        "network/lab/Connection.Dockerfile.dockerignore",
        "network/connection_compare.py",
    ):
        path = base.ROOT / name
        if path.stat().st_size > FILE_BYTES:
            raise ValueError("소스 파일 상한 초과")
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


class ConnectionLab(base.PacketLab):
    def __init__(self, output, scenario, *, seconds=45):
        if scenario not in SCENARIOS:
            raise ValueError("연결 수명주기 시나리오 오류")
        super().__init__(output, "normal", seconds=seconds)
        self.scenario = scenario
        self.run_id = "cs-connection-" + uuid.uuid4().hex

    def server_command(self):
        # PID 1을 유지해 종료된 서버 worker의 tmpfs 증거도 exec로 회수한다.
        return ["sleep", "infinity"]

    def preserve_role(self, cid, role):
        allowed = SERVER_FILES if role == "server" else CLIENT_FILES
        self.preserve(
            cid,
            worker_path="/opt/lab/connection_worker.py",
            quiescent_args=(self.run_id, role),
            allowed=allowed,
        )
        # 회수 직후에도 원본 바이트를 대조한다. 유실/변경 시 원본 컨테이너를 남긴다.
        self.retained_containers.add(cid)
        for name in sorted(allowed):
            path = self.output / name
            if path.is_file():
                if name in ("client.json", "server.json") and path.stat().st_size > LOG_BYTES:
                    raise ValueError("소켓 로그별 64KiB 상한 초과")
                checksum = self.call("exec", cid, "sha256sum", "/run/evidence/" + name)
                fingerprint(path, checksum.stdout.split()[0])
        self.retained_containers.remove(cid)

    def experiment(self):
        self.preflight()
        image = json.loads(self.call("image", "inspect", IMAGE).stdout)[0]
        if image["Config"].get("Labels", {}).get(IMAGE_LABEL) != "connection-v1":
            raise ValueError("전용 연결 이미지 아님; 명시적 build 필요")
        self.image_id = image["Id"]
        base.save(
            self.output / "image.json",
            {
                "id": self.image_id,
                "tags": image.get("RepoTags"),
                "layers": image.get("RootFS"),
                "size": image["Size"],
                "source_sha256": source_fingerprints(),
            },
        )
        self.create_owned("network")
        server, client = self.create_owned("server"), self.create_owned("client")
        target, source = self.verify_pair(server, client)
        actual = self.call("exec", client, "sha256sum", *IMAGE_SOURCES.values()).stdout
        expected = {
            destination: hashlib.sha256((base.ROOT / name).read_bytes()).hexdigest()
            for name, destination in IMAGE_SOURCES.items()
        }
        parsed = dict(reversed(line.split()) for line in actual.splitlines())
        if parsed != expected:
            raise ValueError("실제 이미지 worker/캡처와 작업 소스 바이트 불일치; build 필요")
        versions = {"image_sources": parsed}
        for cmd in (("uname", "-a"), ("python3", "--version"), ("tcpdump", "--version")):
            value = self.call("exec", client, *cmd)
            versions[cmd[0]] = value.stdout + value.stderr
        base.save(self.output / "versions.json", versions)
        route = json.loads(self.call("exec", client, "ip", "-j", "route", "get", target).stdout)[0]
        if route.get("dev") != "eth0" or route.get("prefsrc") != source:
            raise ValueError("소유 인터페이스/주소 불일치")
        server_started, client_started = False, False
        try:
            server_started = True
            self.call(
                "exec",
                "-d",
                server,
                "python3",
                "/opt/lab/connection_worker.py",
                "serve",
                self.scenario,
                self.run_id,
            )
            ready = time.monotonic() + 3
            while not self.call(
                "exec", server, "ss", "-H", "-lnt", f"sport = :{PORT}"
            ).stdout.strip():
                if time.monotonic() >= ready:
                    raise TimeoutError("합성 서버 준비 실패")
                time.sleep(0.02)
            client_started = True
            self.call(
                "exec",
                client,
                "timeout",
                "--signal=TERM",
                "--kill-after=3",
                "21",
                "python3",
                "/opt/lab/connection_worker.py",
                "trial",
                self.scenario,
                target,
                source,
                self.run_id,
                check=False,
                timeout=24,
            )
        finally:
            failures = []
            for started, cid, role in (
                (client_started, client, "client"),
                (server_started, server, "server"),
            ):
                if started:
                    try:
                        self.preserve_role(cid, role)
                    except (Exception, KeyboardInterrupt) as exc:
                        failures.append(f"{role}: {type(exc).__name__}: {exc}")
            if failures:
                raise RuntimeError("; ".join(failures))
        config, worker, client_log, server_log, server_result = (
            strict_json((self.output / name).read_bytes())
            for name in (
                "config.json",
                "worker-result.json",
                "client.json",
                "server.json",
                "server-result.json",
            )
        )
        tool = shutil.which("tshark") or "C:/Program Files/Wireshark/tshark.exe"
        version = base.bounded_command([tool, "--version"], timeout=3, env=self.env)
        base.save(self.output / "tshark-version.json", version)
        if version["code"]:
            raise RuntimeError("TShark 버전 조회 실패")
        # -J는 하위 HTTP 필드와 반복 proto를 보존한다. -j/occurrence=f로 축약하지 않는다.
        argv = [
            tool,
            "-n",
            "-2",
            "-r",
            str(self.output / "capture.pcap"),
            "-o",
            "tcp.desegment_tcp_streams:TRUE",
            "-o",
            "http.desegment_body:TRUE",
            "-d",
            "tcp.port==8080," + ("http" if self.scenario.startswith("http_") else "data"),
            "-T",
            "pdml",
            "-J",
            "frame ip tcp http",
        ]
        decoded = base.bounded_command(
            argv,
            timeout=min(5, self.deadline - time.monotonic()),
            env=self.env,
            limit=FILE_BYTES,
        )
        with (self.output / "packets.pdml").open("x", encoding="utf-8", newline="") as stream:
            stream.write(decoded.pop("stdout"))
            stream.flush()
            os.fsync(stream.fileno())
        base.save(self.output / "decoder.json", decoded)
        if decoded["code"]:
            raise RuntimeError("TShark 디코딩 실패/출력 상한; 부분 원본 보존")
        result = compare(
            (self.output / "packets.pdml").read_text(encoding="utf-8"),
            config,
            worker,
            client_log,
            server_log,
            server_result,
        )
        base.save(self.output / "analysis.json", result)
        return result


def suite(root):
    return base.suite(
        root,
        lab_factory=ConnectionLab,
        scenarios=SCENARIOS,
        limits=LIMITS,
        source_hashes=source_fingerprints,
    )


def reanalyze(origin, root):
    """완성된 원본을 읽기 전용으로 검증하고 별도 해시 연결 결과만 만든다.

    Why: 판독 수정이 연결 실험 반복·원본 실패 덮어쓰기로 이어지지 않게 한다.
    Constraints: 고정 증거 루트의 12회 묶음, 파일당 1MiB·회차 4MiB·전체 64MiB·13분.
    Side-effects: Docker/네트워크 호출은 없다. 새 고유 디렉터리만 쓰며 실패 결과도 남긴다.
    """
    origin = Path(origin)
    if origin.is_symlink() or origin.resolve().parent != root.resolve():
        raise ValueError("고정 루트의 원본 실행 묶음만 허용")
    if (origin / "summary.json").stat().st_size > FILE_BYTES:
        raise ValueError("원본 summary 상한 초과")
    summary_raw = (origin / "summary.json").read_bytes()
    summary_hash = hashlib.sha256(summary_raw).hexdigest()
    fingerprint(origin / "summary.json", (origin / "summary.sha256").read_text().split()[0])
    original = strict_json(summary_raw)
    fingerprint(origin / "plan.json", original["plan_sha256"])
    trials = original.get("trials", [])
    expected = [(mode, repetition) for mode in SCENARIOS for repetition in range(1, 4)]
    if [(t.get("scenario"), t.get("repetition")) for t in trials] != expected:
        raise ValueError("원본 시나리오/회차 순서 오류")
    directory = create_run_directory(root)
    started = time.monotonic()
    references = {
        "action": "analyze",
        "origin": str(origin.resolve()),
        "source_summary_sha256": summary_hash,
        "source_plan_sha256": original["plan_sha256"],
        "analyzer_source_sha256": source_fingerprints(),
        "limits": LIMITS,
    }
    base.save(directory / "references.json", references)
    results, total = [], 0
    interrupted = False
    for trial in trials:
        mode, repetition = trial["scenario"], trial["repetition"]
        label = f"{mode}-{repetition}"
        outcome = {
            "scenario": mode,
            "repetition": repetition,
            "passed": False,
            "original_error": trial.get("error"),
            "source_manifest_sha256": trial.get("manifest_sha256"),
        }
        try:
            if interrupted:
                raise InterruptedError("not_started: user_interrupt")
            if time.monotonic() - started >= 720:
                raise TimeoutError("오프라인 분석 전체 시간 상한")
            source = origin / label
            if source.is_symlink() or source.resolve().parent != origin.resolve():
                raise ValueError("원본 회차 경로 오류")
            if (source / "manifest.json").stat().st_size > FILE_BYTES:
                raise ValueError("manifest 용량 초과")
            _, raw = fingerprint(source / "manifest.json", trial["manifest_sha256"])
            if raw is None:
                raise ValueError("manifest 용량 초과")
            manifest = strict_json(raw)
            if manifest["result"]["run_id"] != trial["run_id"]:
                raise ValueError("다른 실행 manifest")
            files = manifest.get("files", {})
            if not 0 < len(files) <= 32:
                raise ValueError("manifest 파일 개수 오류")
            size = 0
            for name, info in files.items():
                if not isinstance(name, str) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", name
                ):
                    raise ValueError("manifest 파일 경로 오류")
                if type(info.get("bytes")) is not int or not 0 <= info["bytes"] <= FILE_BYTES:
                    raise ValueError("원본 파일 상한 오류")
                if (source / name).stat().st_size > FILE_BYTES:
                    raise ValueError("원본 파일 상한 초과")
                actual, _ = fingerprint(source / name, info["sha256"])
                if actual["bytes"] != info["bytes"]:
                    raise ValueError("원본 파일 크기 불일치")
                size += actual["bytes"]
            total += size
            if size > LIMITS["trial_bytes"] or total > LIMITS["suite_bytes"]:
                raise ValueError("원본 회차/전체 증거 상한 초과")
            required = CLIENT_FILES | SERVER_FILES | {"packets.pdml", "decoder.json"}
            if not required <= files.keys() or trial.get("remaining_resources"):
                raise ValueError("미완성 증거/정리 실패는 오프라인 성공 판정 금지")
            values = {}
            for name in required:
                if name not in ("capture.pcap", "capture.stdout", "capture.stderr", "packets.pdml"):
                    values[name] = strict_json((source / name).read_bytes())
            if values["decoder.json"]["code"] or values["decoder.json"].get("reason"):
                raise ValueError("실패한 디코딩은 재분석 성공 판정 금지")
            analysis = compare(
                (source / "packets.pdml").read_text(encoding="utf-8"),
                values["config.json"],
                values["worker-result.json"],
                values["client.json"],
                values["server.json"],
                values["server-result.json"],
            )
            outcome.update(
                passed=analysis["passed"], reasons=analysis["reasons"], analysis=analysis
            )
        except (Exception, KeyboardInterrupt) as exc:
            outcome["error"] = type(exc).__name__ + ": " + str(exc)
            interrupted = interrupted or isinstance(exc, KeyboardInterrupt)
        base.save(directory / (label + ".json"), outcome)
        results.append({key: value for key, value in outcome.items() if key != "analysis"})
        print(json.dumps(results[-1], ensure_ascii=False), flush=True)
    summary = {
        "action": "analyze",
        "trials": results,
        "complete": all(t["passed"] for t in results),
        "source_summary_sha256": summary_hash,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "source_evidence_bytes": total,
    }
    base.save(directory / "summary.json", summary)
    base.evidence_manifest(directory, references, limit=LIMITS["suite_bytes"])
    print(str(directory), flush=True)
    return 0 if summary["complete"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", nargs="?", choices=("plan", "build", "run", "analyze"), default="plan"
    )
    parser.add_argument("--suite", type=Path, help="analyze에서만 사용할 고정 루트의 원본 묶음")
    args = parser.parse_args(argv)
    if args.action == "plan":
        print(json.dumps({"scenarios": SCENARIOS, "limits": LIMITS}, ensure_ascii=False, indent=2))
        return 0
    root = base.ROOT / "network/lab/runs/connection"
    if args.action == "analyze":
        if args.suite is None:
            parser.error("analyze에는 --suite 원본 묶음 경로가 필요합니다")
        return reanalyze(args.suite, root)
    if args.suite is not None:
        parser.error("--suite는 analyze에서만 사용합니다")
    if args.action == "run":
        return suite(root)
    root.mkdir(parents=True, exist_ok=True)
    directory = create_run_directory(root)
    lab = ConnectionLab(directory / "build", SCENARIOS[0], seconds=600)
    result = {"action": "build", "passed": False}
    try:
        lab.preflight()
        lab.call(
            "build",
            "-t",
            IMAGE,
            "-f",
            str(base.ROOT / "network/lab/Connection.Dockerfile"),
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
