"""컨트롤러 I/O 어댑터. A의 기존 복구 함수와 B의 기존 알림 함수를 호출한다.

Why: 복구 정책·IncidentReport·패킷 디코더를 재정의하지 않고 로컬 AWS 세션만 사용한다.
Constraints: 지정된 단일 EC2/IPSet, 단일 IP 해제, 유한 SDK/SSH 시간·파일 상한.
Side-effects: preflight는 조회/DryRun이며 run에서만 기존 복구·Slack 함수가 호출된다.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path, PurePosixPath

import boto3
import requests
from botocore.config import Config
from botocore.exceptions import ClientError
from demo_controller import make_report, read_json, save_json, utc_now
from roundtrip_timeline import MAX_BYTES, strict_json, write_summary


class LiveBackend:
    def __init__(self, cfg):
        self.cfg = cfg
        self.repo = Path(__file__).resolve().parents[1]
        self.session = boto3.Session(profile_name=cfg["aws_profile"], region_name=cfg["region"])
        options = Config(connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 1})
        self.ec2 = self.session.client("ec2", config=options)
        self.waf = self.session.client("wafv2", config=options)
        self.logs = self.session.client("logs", config=options)
        self.sts = self.session.client("sts", config=options)
        self.before_ids = set()
        self.before_ms = 0

    @staticmethod
    def sleep(seconds):
        time.sleep(seconds)

    def _ssh_args(self):
        c = self.cfg
        return [
            shutil.which("ssh") or "ssh",
            "-F",
            os.devnull,
            "-i",
            c["ssh_key"],
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + c["known_hosts"],
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
            f"{c['ssh_user']}@{c['source_ip']}",
        ]

    @staticmethod
    def _ssh_env():
        # 로컬 프로필/키/웹훅이 SendEnv 또는 자식 환경을 통해 원격으로 넘어가지 않게 분리한다.
        return {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("AWS_") and k != "SLACK_WEBHOOK_URL"
        }

    def _remote(self, op, run_id=None, scenario=None, approval=None, timeout=20, folder=None):
        c = self.cfg
        request = {
            "op": op,
            "root": c["remote_root"],
            "assets": c["assets"],
            "target_ip": c["target_ip"],
            "origin": c["web_origin"],
            "source_ip": c["source_ip"],
            "interface": c["interface"],
            "attacker_instance_id": c["attacker_instance_id"],
            "account_id": c["account_id"],
            "region": c["region"],
        }
        if run_id is not None:
            request.update(run_id=run_id, scenario=scenario)
        if approval is not None:
            request["approval"] = approval
        code = base64.b64encode(Path(__file__).with_name("demo_remote.py").read_bytes()).decode()
        bootstrap = f"import base64;exec(compile(base64.b64decode('{code}'),'demo_remote','exec'))"
        command = shlex.join(
            [
                "sudo",
                "-n",
                c["remote_root"] + "/runtime/python/bin/python3.12",
                "-B",
                "-c",
                bootstrap,
            ]
        )
        response = subprocess.run(
            self._ssh_args() + [command],
            input=json.dumps(request).encode(),
            capture_output=True,
            timeout=timeout,
            env=self._ssh_env(),
        )
        if len(response.stdout) + len(response.stderr) > MAX_BYTES // 2:
            raise ValueError("SSH 메타데이터 상한")
        if folder is not None:
            save_json(
                folder / f"rpc-{op}.private.json",
                {
                    "returncode": response.returncode,
                    "stdout_base64": base64.b64encode(response.stdout).decode(),
                    "stderr_base64": base64.b64encode(response.stderr).decode(),
                },
            )
        result = strict_json(response.stdout)
        if response.returncode or "remote_error" in result:
            raise RuntimeError("승인 노드 동작 실패")
        return result

    def _target(self):
        c = self.cfg
        reply = self.ec2.describe_instances(InstanceIds=[c["target_instance_id"]])
        target = reply["Reservations"][0]["Instances"][0]
        if (
            target["InstanceId"] != c["target_instance_id"]
            or target.get("PublicIpAddress") != c["target_ip"]
            or target["State"]["Name"] != "running"
        ):
            raise ValueError("현재 타깃 식별/정상성 불일치")
        return target

    def _ipset(self):
        c = self.cfg
        return self.waf.get_ip_set(
            Name=c["waf_ipset_name"], Scope="REGIONAL", Id=c["waf_ipset_id"]
        )["IPSet"]

    def _source_blocked(self, item):
        address = ipaddress.ip_address(self.cfg["source_ip"])
        return any(address in ipaddress.ip_network(cidr) for cidr in item.get("Addresses", []))

    def webhook(self):
        path = Path(self.cfg["slack_webhook_file"])
        raw = path.read_text(encoding="utf-8-sig").strip() if path.is_file() else ""
        value = raw.removeprefix("SLACK_WEBHOOK_URL=").strip() or os.getenv("SLACK_WEBHOOK_URL", "")
        from urllib.parse import urlsplit

        parsed = urlsplit(value)
        if (
            len(value) > 2048
            or parsed.scheme != "https"
            or parsed.netloc != "hooks.slack.com"
            or not parsed.path.startswith("/services/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("로컬 Slack 웹훅 미설정/형식 오류")
        return value

    def _grafana(self, start_ms=None, output_path=None):
        """기존 패널의 실제 조회만 검증한다. No data를 공격 0건이나 실측 성공으로 쓰지 않는다."""
        c = self.cfg
        values = dict(
            line.split("=", 1)
            for line in Path(c["grafana_admin_file"]).read_text(encoding="utf-8-sig").splitlines()
            if "=" in line
        )
        base = c["grafana_url"]
        session = requests.Session()
        session.trust_env = False
        try:
            anonymous = session.get(base + "/api/dashboards/uid/cloudshield-p5-2", timeout=3)
            if anonymous.status_code != 401:
                raise ValueError("Grafana 익명 접근 차단 미확인")
            session.auth = (values["GF_SECURITY_ADMIN_USER"], values["GF_SECURITY_ADMIN_PASSWORD"])
            response = session.get(base + "/api/dashboards/uid/cloudshield-p5-2", timeout=5)
            response.raise_for_status()
            queries = []
            for panel in response.json()["dashboard"]["panels"]:
                for target in panel.get("targets", []):
                    query = dict(target)
                    query.update(
                        refId=str(panel["id"]) + target["refId"], intervalMs=1000, maxDataPoints=200
                    )
                    queries.append(query)
            if len(queries) != 5:
                raise ValueError("기존 Grafana 쿼리 구성 변경")
            now = int(time.time() * 1000)
            lower = (now - 1_800_000 if start_ms is None else start_ms - 60000) // 60000 * 60000
            upper = ((now + 59999) // 60000 * 60000) if start_ms is not None else now
            response = session.post(
                base + "/api/ds/query",
                json={
                    "from": str(lower),
                    "to": str(upper),
                    "queries": queries,
                },
                timeout=25,
            )
            response.raise_for_status()
            results = response.json()["results"]
            if output_path is not None:
                save_json(
                    output_path,
                    {"from_ms": lower, "to_ms": upper, "queries": queries, "results": results},
                )
            for query in queries:
                item = results[query["refId"]]
                statuses = {
                    frame.get("schema", {}).get("meta", {}).get("custom", {}).get("Status")
                    for frame in item.get("frames", [])
                }
                if item.get("status") != 200 or item.get("error") or statuses != {"Complete"}:
                    raise ValueError("Grafana 쿼리 미완료/실패")
            return {"query_refs": sorted(results), "query_status": "Complete"}
        finally:
            session.close()

    def preflight(self, scenario):
        c = self.cfg
        result = {
            "mode": "preflight",
            "checked_at": utc_now(),
            "blockers": [],
            "resource_changes": False,
            "slack_message_sent": False,
            "waf_update_permission": "owner_authorized_not_live_tested",
        }
        checks = {
            "caller": lambda: self.sts.get_caller_identity(),
            "target": self._target,
            "ipset": self._ipset,
            "remote": lambda: self._remote("preflight"),
            "webhook": self.webhook,
            "grafana": self._grafana,
        }
        for key, call in checks.items():
            try:
                value = call()
                if key == "caller":
                    if value["Account"] != c["account_id"] or value["Arn"] != c["principal_arn"]:
                        raise ValueError("승인 AWS 신원 불일치")
                elif key == "target":
                    if {g["GroupId"] for g in value["SecurityGroups"]} != {c["baseline_sg_id"]}:
                        raise ValueError("기존 차단/SG 혼합 상태")
                elif key == "ipset" and self._source_blocked(value):
                    raise ValueError("기존 공격 IP 차단 잔류")
                elif key == "remote" and not value["identity_matches"]:
                    raise ValueError("공격 노드 신원 불일치")
                result[key + "_verified"] = True
                if key == "grafana":
                    result["grafana_queries"] = value
            except Exception as exc:
                result["blockers"].append(key + ":" + type(exc).__name__)
        try:
            self.ec2.modify_instance_attribute(
                InstanceId=c["target_instance_id"], Groups=[c["baseline_sg_id"]], DryRun=True
            )
            result["blockers"].append("ec2_dry_run:unexpected_success")
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            result["ec2_restore_permission"] = code
            if code != "DryRunOperation":
                result["blockers"].append("ec2_dry_run:" + code)
        for group in {c["orchestrator_log_group"], c["auth_log_group"], c["nginx_log_group"]}:
            try:
                reply = self.logs.describe_log_groups(logGroupNamePrefix=group, limit=1)
                if not any(x["logGroupName"] == group for x in reply.get("logGroups", [])):
                    raise ValueError("필수 로그 그룹 없음")
            except Exception as exc:
                result["blockers"].append("log_group:" + type(exc).__name__)
        if scenario != "web" and c["require_key_auth"]:
            if not c["target_auth_user"] or not c["target_auth_key"]:
                result["blockers"].append("target_key_auth:not_configured")
            elif not Path(c["target_auth_key"]).is_file():
                result["blockers"].append("target_key_auth:key_file_missing")
            else:
                found = subprocess.run(
                    [
                        shutil.which("ssh-keygen") or "ssh-keygen",
                        "-F",
                        c["target_ip"],
                        "-f",
                        c["known_hosts"],
                    ],
                    capture_output=True,
                    timeout=5,
                )
                if found.returncode:
                    result["blockers"].append("target_key_auth:host_key_missing")
        result["ssh_key_auth_required"] = c["require_key_auth"]
        result["full_p5_key_auth_dod_verified"] = False
        return result

    def _events(self, group, start_ms, pattern):
        events, token, seen = [], None, set()
        for _ in range(8):
            args = {
                "logGroupName": group,
                "startTime": start_ms,
                "endTime": int(time.time() * 1000),
                "filterPattern": pattern,
                "limit": 100,
            }
            if token:
                args["nextToken"] = token
            page = self.logs.filter_log_events(**args)
            for event in page.get("events", []):
                if event["eventId"] not in seen:
                    events.append(event)
                    seen.add(event["eventId"])
            if len(events) > 200 or len(json.dumps(events).encode()) > MAX_BYTES // 2:
                raise ValueError("CloudWatch 관측 상한")
            previous, token = token, page.get("nextToken")
            if not token or token == previous:
                return events
        raise ValueError("CloudWatch 페이지 수집 미완료")

    @staticmethod
    def _metrics(events):
        results = []
        for event in events:
            message = event["message"]
            try:
                record = strict_json(message[message.index("{") :].encode())
                if isinstance(record.get("message"), str):
                    record = strict_json(record["message"].encode())
            except (ValueError, TypeError):
                if "ThreatRemediatedMetric" in message:
                    raise ValueError("손상된 서버 메트릭") from None
                continue
            if record.get("event_type") == "ThreatRemediatedMetric":
                results.append(record)
        return results

    def start(self, run_id, scenario, approval, folder):
        c = self.cfg
        if {g["GroupId"] for g in self._target()["SecurityGroups"]} != {c["baseline_sg_id"]}:
            raise ValueError("다음 회차 전 SG 정상성 미확인")
        if self._source_blocked(self._ipset()):
            raise ValueError("다음 회차 전 WAF 정상성 미확인")
        self.before_ms = int(time.time() * 1000)
        old = self._events(
            c["orchestrator_log_group"],
            self.before_ms - 300_000,
            '"ThreatRemediatedMetric" "' + c["source_ip"] + '"',
        )
        self.before_ids = {m.get("incident_id") for m in self._metrics(old)}
        save_json(folder / "previous-incidents.private.json", {"events": old})
        return self._remote("start", run_id, scenario, approval, folder=folder)

    def attack(self, run_id, scenario, approval, folder):
        return self._remote("attack", run_id, scenario, approval, timeout=105, folder=folder)

    def incident(self, attack, scenario, folder):
        c = self.cfg
        deadline = time.monotonic() + 8
        metrics, raw = [], []
        while True:
            raw = self._events(
                c["orchestrator_log_group"],
                self.before_ms,
                '"ThreatRemediatedMetric" "' + c["source_ip"] + '"',
            )
            metrics = [
                m
                for m in self._metrics(raw)
                if m.get("incident_id") not in self.before_ids
                and m.get("source_ip") == c["source_ip"]
            ]
            ids = {m.get("incident_id") for m in metrics}
            if ids or time.monotonic() >= deadline:
                break
            self.sleep(1)
        source = self._events(
            c["auth_log_group"] if scenario == "ssh" else c["nginx_log_group"],
            self.before_ms,
            '"' + c["source_ip"] + '"',
        )
        save_json(
            folder / "server-evidence.private.json",
            {
                "metric_events": raw,
                "target_events": source,
                "basis": "new incident, source, approved target stream, bounded run window",
            },
        )
        if (
            len(ids) != 1
            or not metrics
            or any(m.get("remediation_success") is not True for m in metrics)
        ):
            raise ValueError("같은 실행의 단일 성공 사건 미확인")
        if not source or any(c["target_instance_id"] not in e["logStreamName"] for e in source):
            raise ValueError("타깃 로그 스트림 연결 미확인")
        if scenario == "ssh" and len(source) < 5:
            raise ValueError("인증 실패 원본 부족")
        report = make_report(metrics[-1], c, scenario, source)
        save_json(folder / "incident-report.private.json", report.model_dump())
        return report

    def quiesce(self, run_id, scenario):
        return self._remote("stop_attack", run_id, scenario)

    def restore(self, scenario, folder):
        # WAF CLI는 목록 조회가 필요하므로, 이미 승인된 ID를 받는 A 함수를 직접 재사용한다.
        # 새 엔진이나 목록 전체 해제를 만들지 않는다. 각 계층은 실패와 무관하게 한 번씩 시도한다.
        project = str(Path(__file__).resolve().parents[1])
        if project not in sys.path:
            sys.path.insert(0, project)
        from scripts.restore_baseline_sg import restore_baseline_security_group

        from remediation.remediation import unblock_ip_wafv2

        c = self.cfg
        result = {
            "requested_at": utc_now(),
            "quarantine_restored": False,
            "waf_unblocked": False,
            "functions": {},
            "errors": [],
        }
        incident_path = folder / "incident-report.private.json"
        result["incident_id"] = (
            read_json(incident_path)["incident_id"] if incident_path.is_file() else None
        )
        for name, action in [
            (
                "l4",
                lambda: restore_baseline_security_group(
                    instance_id=c["target_instance_id"],
                    baseline_sg_id=c["baseline_sg_id"],
                    ec2_client=self.ec2,
                ),
            ),
            (
                "l7",
                lambda: unblock_ip_wafv2(
                    source_ip=c["source_ip"],
                    unblock_all=False,
                    ipset_name=c["waf_ipset_name"],
                    ipset_id=c["waf_ipset_id"],
                    scope="REGIONAL",
                    waf_client=self.waf,
                    max_retries=1,
                ),
            ),
        ]:
            entry = {"started_at": utc_now(), "success": False}
            try:
                value = action()
                entry["value"] = value
                entry["success"] = (
                    value.get("status") in {"success", "unchanged"}
                    if name == "l4"
                    else value is True
                )
            except Exception as exc:
                entry["error_type"] = type(exc).__name__
                result["errors"].append(name + ":" + type(exc).__name__)
            entry["ended_at"] = utc_now()
            result["functions"][name] = entry
        result["function_completed_at"] = utc_now()
        try:
            result["quarantine_restored"] = result["functions"]["l4"]["success"] and {
                g["GroupId"] for g in self._target()["SecurityGroups"]
            } == {c["baseline_sg_id"]}
        except Exception as exc:
            result["errors"].append("l4_verify:" + type(exc).__name__)
        try:
            result["waf_unblocked"] = result["functions"]["l7"][
                "success"
            ] and not self._source_blocked(self._ipset())
        except Exception as exc:
            result["errors"].append("l7_verify:" + type(exc).__name__)
        result["configuration_checked_at"] = utc_now()
        save_json(folder / "restore.private.json", result)
        return result

    def probe(self, run_id, scenario):
        try:
            return self._remote("probe", run_id, scenario, timeout=8)
        except Exception as exc:
            return {"error_type": type(exc).__name__, "observed_at_controller": utc_now()}

    def key_auth(self, folder):
        c = self.cfg
        proxy_args = self._ssh_args()[:-1] + ["-W", "%h:%p", self._ssh_args()[-1]]
        proxy = subprocess.list2cmdline(proxy_args) if os.name == "nt" else shlex.join(proxy_args)
        command = [
            shutil.which("ssh") or "ssh",
            "-F",
            os.devnull,
            "-i",
            c["target_auth_key"],
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=" + c["known_hosts"],
            "-o",
            "ConnectTimeout=3",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ProxyCommand=" + proxy,
            f"{c['target_auth_user']}@{c['target_ip']}",
            "true",
        ]
        try:
            response = subprocess.run(command, capture_output=True, timeout=5, env=self._ssh_env())
            result = {"exit_code": response.returncode, "success": response.returncode == 0}
        except subprocess.TimeoutExpired:
            result = {"exit_code": 124, "success": False}
        save_json(folder / "ssh-key-auth.private.json", result)
        return result["success"]

    def notify(self, report, payload, folder):
        from reporter.slack_notifier import send_recovery_slack_alert

        record = {"invoked_at": utc_now(), "incident_id": report.incident_id, "payload": payload}
        success = send_recovery_slack_alert(
            report=report,
            recovery_result=payload,
            webhook_url=self.webhook(),
            timeout=3,
            max_retries=0,
        )
        record.update(returned_at=utc_now(), success=success, slack_original_ts=None)
        save_json(folder / "slack-recovery.private.json", record)
        return success

    def stop(self, run_id, scenario):
        return self._remote("stop", run_id, scenario)

    def collect(self, run_id, scenario, folder):
        manifest = self._remote("manifest", run_id, scenario)
        if not isinstance(manifest.get("files"), list) or len(manifest["files"]) > 32:
            raise ValueError("회수 파일 개수 상한")
        save_json(folder / "remote-manifest.private.json", manifest)
        base = f"{self.cfg['remote_root']}/root-evidence/{run_id}/{scenario}/"
        seen = set()
        for entry in manifest["files"]:
            relative = PurePosixPath(entry["path"])
            if relative.is_absolute() or ".." in relative.parts or "\\" in entry["path"]:
                raise ValueError("회수 경로 이탈")
            if not relative.parts or any(
                not re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in relative.parts
            ):
                raise ValueError("회수 파일 이름 오류")
            if entry["path"].casefold() in seen:
                raise ValueError("회수 경로 중복")
            seen.add(entry["path"].casefold())
            limit = 1024**3 if relative.suffix == ".pcap" else MAX_BYTES
            if type(entry["bytes"]) is not int or not 0 <= entry["bytes"] <= limit:
                raise ValueError("회수 파일 크기 상한")
            if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
                raise ValueError("회수 해시 형식 오류")
            dest = folder / "remote" / relative
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            partial = dest.with_name(dest.name + ".partial")
            command = shlex.join(["sudo", "-n", "cat", "--", base + entry["path"]])
            with partial.open("xb") as out:
                response = subprocess.run(
                    self._ssh_args() + [command],
                    stdout=out,
                    stderr=subprocess.PIPE,
                    timeout=180,
                    env=self._ssh_env(),
                )
            if response.returncode or partial.stat().st_size != entry["bytes"]:
                raise RuntimeError("증거 전송 실패/크기 불일치")
            digest = hashlib.sha256()
            with partial.open("rb") as stream:
                for chunk in iter(lambda: stream.read(MAX_BYTES), b""):
                    digest.update(chunk)
            if digest.hexdigest() != entry["sha256"]:
                raise ValueError("증거 전송 해시 불일치")
            os.link(partial, dest)
            partial.unlink()

    def timeline(self, attack, report, folder, scenario):
        if not attack or not attack.get("runner_run_id"):
            raise ValueError("상위 러너 ID 미확보")
        run_id = attack["runner_run_id"]
        binding = {"run_id": run_id, "scenario": scenario, "target_key": "approved-target"}
        entries = []

        def add(identifier, form, path, clock):
            entries.append(
                {
                    **binding,
                    "evidence_id": identifier,
                    "format": form,
                    "path": str(path.resolve()),
                    "clock_id": clock,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            )

        events = folder / "remote" / "runner" / run_id / "events.jsonl"
        add("runner", "runner_events", events, "attacker")
        for index, pcap in enumerate(sorted((folder / "remote").rglob("*.pcap"))):
            add("pcap-" + str(index), "opaque", pcap, "attacker")
        recovery = read_json(folder / "restore.private.json")
        add("restore", "opaque", folder / "restore.private.json", "controller")
        server = folder / "server-evidence.private.json"
        if server.is_file():
            add("server", "opaque", server, "controller")
        control = []
        for kind, time_value in [
            ("recovery_requested", recovery["requested_at"]),
            ("recovery_started", recovery["functions"]["l4"]["started_at"]),
            ("recovery_api_completed", recovery["function_completed_at"]),
        ]:
            control.append(
                {
                    "event_id": kind,
                    "kind": kind,
                    "time": time_value,
                    "source_kind": "cloud_a",
                    "backing_evidence_id": "restore",
                    "locator": "approved_A_function_observed_boundary/" + kind,
                }
            )
        if recovery["quarantine_restored"] and recovery["waf_unblocked"]:
            control.append(
                {
                    "event_id": "configuration",
                    "kind": "configuration_verified",
                    "time": recovery["configuration_checked_at"],
                    "source_kind": "cloud_a",
                    "backing_evidence_id": "restore",
                    "locator": "configuration_checked_at",
                }
            )
        if report is not None:
            for event in control:
                event["incident_id"] = report.incident_id
        save_json(folder / "control-observations.private.json", {**binding, "events": control})
        add("control", "observations", folder / "control-observations.private.json", "controller")
        probes = read_json(folder / "recovery-probes.private.json")["probes"]
        add("probe-raw", "opaque", folder / "recovery-probes.private.json", "attacker")
        observations = []
        for index, probe in enumerate(probes):
            if "ended_at" not in probe:
                continue
            item = {
                "event_id": "recovery-probe-" + str(index),
                "kind": "probe",
                "time": probe["ended_at"],
                "source_kind": "tcp_probe" if scenario == "ssh" else "http_probe",
                "backing_evidence_id": "probe-raw",
                "locator": f"probes/{index}",
                "connection_kind": "new",
                "outcome": probe["state"] if scenario == "ssh" else "http",
            }
            if scenario == "web":
                item["http_status"] = probe["http_status"]
            observations.append(item)
        save_json(folder / "probe-observations.private.json", {**binding, "events": observations})
        add("probe", "observations", folder / "probe-observations.private.json", "attacker")
        manifest = {
            **binding,
            "schema_version": "cloudshield-roundtrip-input-v1",
            "incident_id": report.incident_id if report else None,
            "clocks": {k: {"max_error_seconds": None} for k in ["controller", "attacker"]},
            "measurement_limits": {
                "probe_interval_seconds": None,
                "probe_timeout_seconds": "0.8" if scenario == "ssh" else "1",
            },
            "evidence": entries,
        }
        save_json(folder / "timeline-input.private.json", manifest)
        write_summary(
            folder / "timeline-input.private.json", folder / "timeline-summary.private.json"
        )
        if "started_at" in attack:
            start_ms = int(datetime.fromisoformat(attack["started_at"]).timestamp() * 1000)
            self._grafana(start_ms, folder / "grafana-results.private.json")
