"""로컬 단일 데모 진입점. 기존 공격·A 복구·B 알림·왕복 분석기를 연결한다.

Why: AWS 변경 권한을 공격 노드에 넘기지 않고 같은 실행의 공격/복구/증거를 조율한다.
Constraints: 기본 plan, 별도 유효 승인, SSH/Web 각 1회, 캡처 120초, 무제한 재시도 없음.
Side-effects: run --execute만 공격·복구·알림을 수행한다. preflight는 조회와 권한 DryRun만 한다.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import demo_attack_runner as runner
from roundtrip_timeline import MAX_BYTES, strict_json

SCHEMA = "cloudshield-demo-controller-v1"
FIELDS = {
    "schema_version",
    "aws_profile",
    "account_id",
    "principal_arn",
    "region",
    "attacker_instance_id",
    "source_ip",
    "target_instance_id",
    "target_ip",
    "baseline_sg_id",
    "quarantine_sg_id",
    "waf_ipset_name",
    "waf_ipset_id",
    "web_origin",
    "ssh_user",
    "ssh_key",
    "known_hosts",
    "remote_root",
    "interface",
    "assets",
    "evidence_root",
    "approval_file",
    "slack_webhook_file",
    "orchestrator_log_group",
    "auth_log_group",
    "nginx_log_group",
    "target_auth_user",
    "target_auth_key",
    "grafana_url",
    "grafana_admin_file",
    "require_key_auth",
}


def utc_now():
    return datetime.now(UTC).isoformat()


def save_json(path, value):
    """기존 왕복 계측기의 fsync/hard-link 패턴을 계승해 부분 JSON·덮어쓰기를 막는다."""
    raw = (json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n").encode()
    if len(raw) > MAX_BYTES:
        raise ValueError("컨트롤러 메타데이터 상한")
    fd, temporary = tempfile.mkstemp(prefix=".controller-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.link(temporary, path)
    finally:
        Path(temporary).unlink()


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("입력 파일/용량 오류")
    return strict_json(path.read_bytes())


def outside_git(path):
    resolved = path.resolve()
    if not path.is_absolute() or path.is_symlink() or resolved != path.absolute():
        raise ValueError("비공개 경로는 링크 없는 절대 경로여야 합니다")
    if any((p / ".git").exists() for p in (resolved, *resolved.parents)):
        raise ValueError("비공개 원본을 Git 안에 저장할 수 없습니다")
    return resolved


def load_config(path):
    cfg = read_json(path)
    if not isinstance(cfg, dict) or set(cfg) != FIELDS or cfg["schema_version"] != SCHEMA:
        raise ValueError("컨트롤러 구성 필드 오류")
    for key in ("source_ip", "target_ip"):
        cfg[key] = runner.ssh.validate_public_ipv4(cfg[key])
    if cfg["source_ip"] == cfg["target_ip"] or cfg["region"] != "ap-southeast-2":
        raise ValueError("승인 대상/리전 오류")
    for key in ("attacker_instance_id", "target_instance_id"):
        if not re.fullmatch(r"i-[0-9a-f]{8,17}", cfg[key]):
            raise ValueError("인스턴스 식별자 오류")
    if cfg["attacker_instance_id"] == cfg["target_instance_id"]:
        raise ValueError("공격 노드/타깃 혼합")
    for key in ("baseline_sg_id", "quarantine_sg_id"):
        if not re.fullmatch(r"sg-[0-9a-f]{8,17}", cfg[key]):
            raise ValueError("SG 식별자 오류")
    if cfg["baseline_sg_id"] == cfg["quarantine_sg_id"]:
        raise ValueError("Baseline/Quarantine 혼합")
    if not re.fullmatch(r"[0-9]{12}", cfg["account_id"]):
        raise ValueError("계정 식별자 오류")
    if not cfg["principal_arn"].startswith(f"arn:aws:iam::{cfg['account_id']}:user/"):
        raise ValueError("승인된 로컬 사용자 ARN 오류")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", cfg["aws_profile"]):
        raise ValueError("로컬 프로필 이름 오류")
    if cfg["ssh_user"] != "ubuntu":
        raise ValueError("공격 노드 SSH 사용자 오류")
    if not re.fullmatch(r"/home/ubuntu/cloudshield-p5-4-prep-[A-Za-z0-9-]+", cfg["remote_root"]):
        raise ValueError("원격 준비 경로 오류")
    runner.ssh.validate_interface(cfg["interface"])
    if runner.validate_origin(cfg["web_origin"]) != cfg["web_origin"]:
        raise ValueError("승인 origin 오류")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", cfg["waf_ipset_name"]):
        raise ValueError("IPSet 이름 오류")
    if not re.fullmatch(r"[a-f0-9-]{36}", cfg["waf_ipset_id"]):
        raise ValueError("IPSet ID 오류")
    from demo_remote import ASSETS

    if set(cfg["assets"]) != ASSETS or any(
        not re.fullmatch(r"[0-9a-f]{64}", h) for h in cfg["assets"].values()
    ):
        raise ValueError("기존 자산 해시 구성 오류")
    for key in ("ssh_key", "known_hosts", "evidence_root", "approval_file", "slack_webhook_file"):
        outside_git(Path(cfg[key]))
    for key in ("orchestrator_log_group", "auth_log_group", "nginx_log_group"):
        if not re.fullmatch(r"/[A-Za-z0-9_./-]{1,200}", cfg[key]):
            raise ValueError("로그 그룹 오류")
    if cfg["target_auth_user"] is not None and not re.fullmatch(
        r"[a-z_][a-z0-9_-]{0,31}", cfg["target_auth_user"]
    ):
        raise ValueError("키 인증 사용자 오류")
    outside_git(Path(cfg["grafana_admin_file"]))
    if cfg["grafana_url"] != "http://127.0.0.1:3000":
        raise ValueError("승인된 로컬 Grafana 주소만 허용합니다")
    if type(cfg["require_key_auth"]) is not bool:
        raise ValueError("키 인증 검증 여부는 명시적 불리언이어야 합니다")
    if cfg["target_auth_key"] is not None:
        outside_git(Path(cfg["target_auth_key"]))
    return cfg


def load_approval(cfg, scenario):
    path = outside_git(Path(cfg["approval_file"]))
    data = read_json(path)
    if path.stat().st_size > runner.MAX_APPROVAL_BYTES:
        raise ValueError("승인 파일 16KiB 상한")
    if os.name == "posix" and (
        path.stat().st_uid != os.geteuid() or stat.S_IMODE(path.stat().st_mode) != 0o600
    ):
        raise ValueError("승인 파일 소유자/0600 오류")
    approval = runner.parse_approval(data, scenario)
    if approval.source_ipv4 != cfg["source_ip"]:
        raise ValueError("승인 출발지 불일치")
    if scenario != "web" and (
        approval.ec2_ip != cfg["target_ip"] or approval.instance_id != cfg["target_instance_id"]
    ):
        raise ValueError("승인 타깃 불일치")
    if scenario != "ssh" and approval.alb_origin != cfg["web_origin"]:
        raise ValueError("승인 Web origin 불일치")
    return data


def make_report(metric, cfg, scenario, auth_events):
    """서버가 발급한 ID·룰을 기존 보안 매퍼에 전달한다. 기본/새 사건 ID를 만들지 않는다."""
    from contracts.events import SyslogAuthEvent
    from detection.incident_mapper import map_threat_to_incident

    if metric.get("source_ip") != cfg["source_ip"] or not re.fullmatch(
        r"INC-[A-Za-z0-9-]{1,100}", metric.get("incident_id", "")
    ):
        raise ValueError("서버 사건 연결 오류")
    accounts = []
    if scenario == "ssh":
        for event in auth_events:
            parsed = SyslogAuthEvent.parse_line(event["message"])
            if parsed is not None and parsed.source_ip == cfg["source_ip"]:
                accounts.append(parsed.username)
        if not accounts or set(accounts) != {"cloudshield_test"}:
            raise ValueError("서버 인증 실패 계정 근거 미확인")
    report = map_threat_to_incident(
        is_threat=True,
        rule_name=metric["rule_name"],
        source_ip=cfg["source_ip"],
        target_accounts=tuple(accounts),
        target_identifier=cfg["target_instance_id"],
        incident_id=metric["incident_id"],
    )
    if report.action_required != metric.get("action_required"):
        raise ValueError("서버 액션/기존 매퍼 불일치")
    if (scenario == "web") != (report.action_required == "BLOCK_WAF"):
        raise ValueError("서버 시나리오 혼합")
    if scenario == "ssh" and report.action_required != "BLOCK_AND_QUARANTINE":
        raise ValueError("이번 단일 계정 Hydra 시나리오와 다른 서버 판정")
    return report


def run_demo(cfg, backend, approval, scenario="all"):
    """공격 요청 후 실패해도 승인된 범위의 복구를 시도하고 단계별 실패를 보존한다.

    Why: 전송 실패로 공격 완료를 못 읽어도 승인 타깃을 차단 상태로 방치하지 않는다.
    Constraints: 승인 ID 1회 소비, 시나리오별 새 디렉터리·120초 캡처, 재공격 없음.
    Side-effects: 기존 A CLI·B 알림만 호출. 부분 실패/저장 실패/알림 실패는 전체 성공이 아니다.
    """
    checks = backend.preflight(scenario)
    if checks["blockers"]:
        raise ValueError("실행 전 필수 조건 미충족")
    root = outside_git(Path(cfg["evidence_root"]))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    guard = root / (".approval-" + hashlib.sha256(approval["approval_id"].encode()).hexdigest())
    save_json(guard, {"consumed_at": utc_now()})
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(6)
    directory = runner.create_run_directory(root, run_id=run_id)
    save_json(directory / "preflight.private.json", checks)
    save_json(directory / "approval.private.json", approval)
    result = {
        "controller_run_id": run_id,
        "started_at": utc_now(),
        "scenarios": [],
        "complete": False,
        "scope": "controller_workflow_only",
        "e2e_sla_verified": False,
        "first_attack_sla": "not_evaluated",
    }
    save_json(directory / "controller-start.private.json", result)
    for selected in ["ssh", "web"] if scenario == "all" else [scenario]:
        runner.parse_approval(approval, selected)
        folder = directory / selected
        folder.mkdir(mode=0o700)
        state = {
            "scenario": selected,
            "failures": [],
            "attack_requested": False,
            "traffic_verified": False,
            "slack_sent": False,
            "complete": False,
        }
        started, report, attack = False, None, None
        deadline = time.monotonic() + 112
        try:
            started = True
            backend.start(run_id, selected, approval, folder)
            save_json(folder / "attack-requested.private.json", {"time": utc_now()})
            state["attack_requested"] = True
            attack = backend.attack(run_id, selected, approval, folder)
            state["attack_exit_code"] = attack["exit_code"]
            if attack["exit_code"] != 0:
                state["failures"].append("attack_or_block_not_completed")
            try:
                report = backend.incident(attack, selected, folder)
                state["incident_id"] = report.incident_id
            except Exception as exc:
                state["failures"].append("incident:" + type(exc).__name__)
        except BaseException as exc:
            state["failures"].append("execution:" + type(exc).__name__)
        finally:
            if state["attack_requested"]:
                try:
                    backend.quiesce(run_id, selected)
                except Exception as exc:
                    state["failures"].append("quiesce:" + type(exc).__name__)
                try:
                    recovery = backend.restore(selected, folder)
                    state["recovery"] = recovery
                    if not recovery["quarantine_restored"] or not recovery["waf_unblocked"]:
                        state["failures"].append("partial_recovery")
                    probes = []
                    probe_deadline = min(deadline, time.monotonic() + 30)
                    for _ in range(20):
                        if time.monotonic() >= probe_deadline:
                            break
                        probe = backend.probe(run_id, selected)
                        probes.append(probe)
                        normal = (
                            probe.get("state") == "connected"
                            if selected == "ssh"
                            else probe.get("http_status") == 200
                        )
                        if normal:
                            state["traffic_verified"] = True
                            break
                        backend.sleep(1)
                    save_json(folder / "recovery-probes.private.json", {"probes": probes})
                    if not state["traffic_verified"]:
                        state["failures"].append("traffic_not_recovered")
                    if selected == "ssh" and not cfg["require_key_auth"]:
                        state["ssh_key_auth_verified"] = None
                        state["unverified_requirements"] = ["ssh_key_auth"]
                    if selected == "ssh" and state["traffic_verified"] and cfg["require_key_auth"]:
                        state["ssh_key_auth_verified"] = backend.key_auth(folder)
                        if not state["ssh_key_auth_verified"]:
                            state["failures"].append("ssh_key_auth_failed")
                    if report is not None:
                        payload = {
                            **recovery,
                            "traffic_verified": state["traffic_verified"],
                            "iam_restored": False,
                            "t_restored_iso": recovery.get("configuration_checked_at")
                            if recovery["quarantine_restored"] and recovery["waf_unblocked"]
                            else None,
                            "verification_status": "controller independent checks",
                            "details": [
                                "독립 관측: 신규 TCP 연결"
                                if selected == "ssh"
                                else "독립 관측: 동일 루트 HEAD HTTP 응답",
                                "SSH 키 인증: " + str(state.get("ssh_key_auth_verified"))
                                if selected == "ssh"
                                else "SSH 키 인증: 미대상",
                            ],
                        }
                        state["slack_sent"] = backend.notify(report, payload, folder)
                        if not state["slack_sent"]:
                            state["failures"].append("slack_failed")
                except BaseException as exc:
                    state["failures"].append("recovery:" + type(exc).__name__)
            if started:
                try:
                    stopped = backend.stop(run_id, selected)
                    if stopped.get("forced_kill_count"):
                        state["failures"].append("capture_forced_stop")
                    if stopped.get("capture_already_stopped_count"):
                        state["failures"].append("capture_ended_before_recovery_observation")
                except Exception as exc:
                    state["failures"].append("capture_stop:" + type(exc).__name__)
                try:
                    backend.collect(run_id, selected, folder)
                    backend.timeline(attack, report, folder, selected)
                except Exception as exc:
                    state["failures"].append("evidence:" + type(exc).__name__)
        state["complete"] = not state["failures"] and state["traffic_verified"]
        save_json(folder / "scenario-result.private.json", state)
        result["scenarios"].append(state)
        if not state["complete"]:
            break
    result["complete"] = (
        bool(result["scenarios"])
        and all(s["complete"] for s in result["scenarios"])
        and (scenario != "all" or len(result["scenarios"]) == 2)
    )
    result["ended_at"] = utc_now()
    save_json(directory / "controller-result.private.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "preflight", "run"), nargs="?", default="plan")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--scenario", choices=("ssh", "web", "all"), default="all")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        cfg = load_config(args.config)
        if args.command == "plan":
            if args.execute:
                raise ValueError("plan에 execute 금지")
            print(
                json.dumps(
                    {
                        "mode": "plan",
                        "scenario": args.scenario,
                        "network_executed": False,
                        "capture_seconds": 120,
                        "capture_packets": 2000,
                        "attack_rounds_per_scenario": 1,
                    }
                )
            )
            return 0
        if args.command == "run" and not args.execute:
            raise ValueError("run에는 별도 execute 필요")
        if args.command == "preflight" and args.execute:
            raise ValueError("preflight에 execute 금지")
        from demo_controller_aws import LiveBackend

        backend = LiveBackend(cfg)
        if args.command == "preflight":
            if args.execute:
                raise ValueError("preflight에 execute 금지")
            result = backend.preflight(args.scenario)
            print(json.dumps(result, ensure_ascii=False))
            return 0 if not result["blockers"] else 2
        approval = load_approval(cfg, args.scenario)
        result = run_demo(cfg, backend, approval, args.scenario)
        print(
            json.dumps(
                {
                    "workflow_complete": result["complete"],
                    "e2e_sla_verified": False,
                    "first_attack_sla": "not_evaluated",
                }
            )
        )
        return 0 if result["complete"] else 3
    except Exception as exc:
        print(json.dumps({"controller_error": type(exc).__name__, "complete": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
