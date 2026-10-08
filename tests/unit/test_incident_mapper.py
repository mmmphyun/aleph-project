# CloudShield 단위 테스트: 결정론적 침해사고 매퍼
# 소유자: 보안 담당
"""결정론적 침해사고 매퍼(incident_mapper.py) 단위 테스트."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.incident import IncidentReport
from detection.incident_mapper import analyze_incident, map_threat_to_incident


@pytest.fixture
def waf_terraform() -> tuple[str, Path]:
    """WAF 정책과 사고 계약의 연결을 실제 Terraform 스키마로 검증한다.

    Constraints:
        Terraform 1.7+와 모듈의 사전 init이 필요하다. Python 전용 개발 환경에서는
        명시적으로 skip하며, WAF PR 검증은 도구를 설치한 환경에서 반드시 실행한다.
    """
    terraform = shutil.which("terraform")
    module = Path(__file__).resolve().parents[2] / "infra/terraform/modules/waf"
    if terraform is None or not (module / ".terraform/providers").is_dir():
        pytest.skip("WAF IaC 검증에는 Terraform 1.7+ 설치 및 모듈 init이 필요합니다.")
    version = json.loads(_run_waf_terraform(terraform, module, "version", "-json").stdout)
    if tuple(int(part) for part in version["terraform_version"].split(".")[:2]) < (1, 7):
        pytest.skip("Terraform mock provider 검증에는 1.7 이상이 필요합니다.")
    return terraform, module


def _run_waf_terraform(
    terraform: str, directory: Path, *arguments: str
) -> subprocess.CompletedProcess[str]:
    """셸을 거치지 않고 로컬 계획·mock 검증만 실행하며 실패 원인을 숨기지 않는다."""
    environment = os.environ.copy()
    environment.update({"TF_IN_AUTOMATION": "1", "CHECKPOINT_DISABLE": "1"})
    result = subprocess.run(
        [terraform, f"-chdir={directory}", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        timeout=90,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def test_waf_terraform_incident_block_policy(waf_terraform: tuple[str, Path]) -> None:
    """BLOCK_WAF의 도착점이 실제 IPSet Block 규칙이며 잘못된 입력이 거부되는지 검증한다."""
    terraform, module = waf_terraform
    _run_waf_terraform(terraform, module, "test", "-no-color")


def test_waf_terraform_preserves_runtime_blocks(
    waf_terraform: tuple[str, Path], tmp_path: Path
) -> None:
    """Lambda가 추가한 /32 주소를 Terraform 재적용이 삭제하는 회귀를 검출한다.

    Why:
        빈 초기 목록과 동적 차단 목록은 소유자가 다르므로 실제 계획 결과에서 보존을
        증명한다. ignore_changes를 제거하면 이 테스트는 빈 주소 덮어쓰기를 검출한다.
    Side-effects:
        로컬 임시 state와 캐시된 provider만 사용한다. refresh를 비활성화하고 검증용
        provider의 모든 계정·메타데이터 조회를 차단하며 apply는 실행하지 않는다.
    """
    terraform, module = waf_terraform
    for source in module.glob("*.tf"):
        shutil.copy2(source, tmp_path / source.name)
    shutil.copy2(module / ".terraform.lock.hcl", tmp_path / ".terraform.lock.hcl")
    (tmp_path / "provider.tf").write_text(
        'provider "aws" {\n'
        '  region                      = "ap-northeast-2"\n'
        '  access_key                  = "testing"\n'
        '  secret_key                  = "testing"\n'
        "  skip_credentials_validation = true\n"
        "  skip_requesting_account_id  = true\n"
        "  skip_metadata_api_check     = true\n"
        "  skip_region_validation     = true\n"
        "}\n",
        encoding="utf-8",
    )
    addresses = ["203.0.113.10/32", "198.51.100.20/32"]
    state = {
        "version": 4,
        "serial": 1,
        "lineage": "33333333-3333-3333-3333-333333333333",
        "outputs": {},
        "resources": [
            {
                "mode": "managed",
                "type": "aws_wafv2_ip_set",
                "name": "blocked",
                "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                "instances": [
                    {
                        "schema_version": 0,
                        "attributes": {
                            "id": "11111111-1111-1111-1111-111111111111",
                            "arn": (
                                "arn:aws:wafv2:ap-northeast-2:123456789012:regional/ipset/"
                                "CloudShield-Block-IPSet/11111111-1111-1111-1111-111111111111"
                            ),
                            "name": "CloudShield-Block-IPSet",
                            "description": "CloudShield runtime-managed IPv4 host block list",
                            "scope": "REGIONAL",
                            "ip_address_version": "IPV4",
                            "addresses": addresses,
                            "tags": {},
                            "tags_all": {},
                        },
                    }
                ],
            }
        ],
    }
    (tmp_path / "terraform.tfstate").write_text(json.dumps(state), encoding="utf-8")
    _run_waf_terraform(
        terraform,
        tmp_path,
        "init",
        "-backend=false",
        "-input=false",
        f"-plugin-dir={module / '.terraform/providers'}",
        "-no-color",
    )
    _run_waf_terraform(
        terraform, tmp_path, "plan", "-refresh=false", "-input=false", "-out=waf.plan", "-no-color"
    )
    plan = json.loads(_run_waf_terraform(terraform, tmp_path, "show", "-json", "waf.plan").stdout)
    change = next(
        resource["change"]
        for resource in plan["resource_changes"]
        if resource["address"] == "aws_wafv2_ip_set.blocked"
    )
    # 태그 업데이트가 함께 계획되어도 차단 목록의 두 기존 주소가 모두 유지되어야 한다.
    assert change["actions"] == ["update"]
    assert set(change["after"]["addresses"]) == set(addresses)


def test_analyze_incident_interface(sample_auth_log_lines: list[str]) -> None:
    """원문 SSH 실패 로그를 IncidentReport 계약 객체로 승격한다.

    Why:
        1차 시그니처 룰 결과가 MITRE ATT&CK 및 공통 사고 계약으로 이어지는지
        보안 담당 영역에서 먼저 고정해 오케스트레이터와 Slack 연계를 안전하게 한다.
    """
    raw_logs = "\n".join(sample_auth_log_lines)
    report = analyze_incident(raw_logs)

    assert isinstance(report, IncidentReport)
    assert report.attack_type == "SSH Password Spraying"
    assert report.mitre_id == "T1110.003"
    assert report.source_ip == "198.51.100.50"
    assert report.target_identifier == "i-0abcd1234ef567890"
    assert report.target_accounts == ("admin", "root", "guest")
    assert report.action_required == "BLOCK_IP_ONLY"
    assert report.risk_level == "MEDIUM"


def test_analyze_incident_maps_t1110_001_to_brute_force_report() -> None:
    """동일 계정 반복 실패는 T1110.001 Password Guessing으로 반환한다."""
    raw_logs = "\n".join(
        [
            "Sep 03 14:20:0"
            f"{index} target-ec2 sshd[1234{index}]: "
            "Failed password for root from 198.51.100.51 port 49152 ssh2"
            for index in range(1, 6)
        ]
    )
    report = analyze_incident(raw_logs)

    assert report.attack_type == "SSH Brute Force"
    assert report.mitre_id == "T1110.001"
    assert report.risk_level == "HIGH"
    assert report.source_ip == "198.51.100.51"
    assert report.target_accounts == ("root",)
    assert report.action_required == "BLOCK_AND_QUARANTINE"


def test_analyze_incident_rejects_non_attack_logs() -> None:
    """정상 로그만 들어오면 계약 객체를 만들지 않고 호출부 판단으로 넘긴다."""
    raw_logs = (
        "Sep 03 14:20:01 target-ec2 sshd[12341]: "
        "Accepted publickey for ubuntu from 192.0.2.10 port 49152 ssh2"
    )

    try:
        analyze_incident(raw_logs)
    except ValueError as exc:
        assert "탐지 가능한 SSH 인증 실패 공격 패턴" in str(exc)
    else:
        raise AssertionError("정상 로그는 IncidentReport로 변환되면 안 된다.")


@pytest.mark.parametrize(
    ("rule_name", "expected_mitre_id", "expected_risk", "expected_action"),
    [
        ("SSH_BRUTE_FORCE", "T1110.001", "HIGH", "BLOCK_AND_QUARANTINE"),
        ("SSH_PASSWORD_SPRAYING", "T1110.003", "MEDIUM", "BLOCK_IP_ONLY"),
    ],
)
def test_map_threat_to_incident_unifies_window_rule_metadata(
    rule_name: str,
    expected_mitre_id: str,
    expected_risk: str,
    expected_action: str,
) -> None:
    """누적 윈도우 판정도 원문 로그 경로와 동일한 MITRE 메타데이터를 사용한다."""
    report = map_threat_to_incident(
        is_threat=True,
        rule_name=rule_name,
        source_ip="198.51.100.52",
        target_accounts=("root", "root", "admin"),
        target_identifier="i-0123456789abcdef0",
        incident_id="INC-WINDOW-SSH-001",
    )

    assert isinstance(report, IncidentReport)
    assert report.incident_id == "INC-WINDOW-SSH-001"
    assert report.mitre_id == expected_mitre_id
    assert report.risk_level == expected_risk
    assert report.action_required == expected_action
    assert report.target_accounts == ("root", "admin")


def test_spraying_accumulated_accounts_preserve_evidence_and_policy() -> None:
    """누적 계정 목록의 순서·중복 제거 및 SSH 전용 권고를 함께 검증한다."""
    accounts = ["admin", "root", "admin", "guest"]
    report = map_threat_to_incident(
        is_threat=True,
        rule_name="SSH_PASSWORD_SPRAYING",
        source_ip="203.0.113.44",
        target_accounts=accounts,
        incident_id="INC-SPRAY-001",
    )
    assert accounts == ["admin", "root", "admin", "guest"]
    assert report.target_accounts == ("admin", "root", "guest")
    assert report.incident_id == "INC-SPRAY-001"
    assert report.mitre_id == "T1110.003"
    assert report.risk_level == "MEDIUM"
    assert report.action_required == "BLOCK_IP_ONLY"
    assert "admin, root, guest" in report.summary_ko
    assert report.recommendations == (
        "출발지 IP 203.0.113.44/32의 SSH 접근을 차단하는 네트워크 정책 적용",
        "비밀번호 기반 SSH 접속 비활성화 및 키 기반 인증 강제",
    )


@pytest.mark.parametrize("accounts", ["admin", b"admin", [""], ["  "], [None], [1]])
def test_mapper_rejects_invalid_account_evidence(accounts: object) -> None:
    """문자 단위 분해와 빈 계정 때문에 부정확한 사고 보고가 생성되는 것을 방지한다."""
    with pytest.raises(ValueError, match="문자열 목록"):
        map_threat_to_incident(
            is_threat=True,
            rule_name="SSH_PASSWORD_SPRAYING",
            source_ip="203.0.113.44",
            target_accounts=accounts,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    ("is_threat", "rule_name", "target_accounts", "message"),
    [
        (False, None, ("root",), "탐지 가능한"),
        (True, "UNKNOWN_RULE", ("root",), "지원하지 않는 탐지 룰"),
        (True, "SSH_BRUTE_FORCE", (), "최소 한 개의 대상 계정"),
    ],
)
def test_map_threat_to_incident_rejects_invalid_decisions(
    is_threat: bool,
    rule_name: str | None,
    target_accounts: tuple[str, ...],
    message: str,
) -> None:
    """비위협·미지 룰·대상 누락은 불완전한 IncidentReport로 승격하지 않는다."""
    with pytest.raises(ValueError, match=message):
        map_threat_to_incident(
            is_threat=is_threat,
            rule_name=rule_name,
            source_ip="198.51.100.52",
            target_accounts=target_accounts,
        )


@pytest.mark.parametrize(
    ("uris", "expected_rule", "expected_mitre"),
    [
        (["/../etc/passwd"], "PATH_TRAVERSAL", "T1595.002"),
        (["/.env"], "SENSITIVE_FILE_PROBING", "T1595.003"),
        (
            ["/admin", "/login", "/backup", "/config", "/debug"],
            "WEB_DIRECTORY_SCANNING",
            "T1595.003",
        ),
    ],
)
def test_web_detection_maps_to_contract_and_waf_card(
    uris: list[str],
    expected_rule: str,
    expected_mitre: str,
) -> None:
    """실제 Nginx 파싱부터 WAF 카드까지 공통 계약을 교차검증한다."""
    from contracts.events import NginxAccessLogEvent
    from detection.rules import evaluate_web_rules
    from reporter.slack_notifier import build_waf_slack_payload

    events = []
    for index, uri in enumerate(uris):
        event = NginxAccessLogEvent.parse_line(
            f"198.51.100.77 - - [28/Sep/2026:11:52:0{index} +0000] "
            f'"GET {uri} HTTP/1.1" 404 150 "-" "curl/8.0" 0.002 "-"'
        )
        assert event is not None
        events.append(event)
    detected, rule = evaluate_web_rules(events)
    assert detected and rule == expected_rule
    report = map_threat_to_incident(
        is_threat=detected,
        rule_name=rule,
        source_ip=events[0].source_ip,
        target_identifier="i-0123456789abcdef0",
        incident_id="INC-WEB-001",
    )
    assert IncidentReport.model_validate_json(report.model_dump_json()) == report
    assert report.target_accounts == ()
    assert report.action_required == "BLOCK_WAF"
    assert report.risk_level == "HIGH"
    assert report.mitre_id == expected_mitre
    assert report.incident_id == "INC-WEB-001"
    assert report.target_identifier == "i-0123456789abcdef0"
    assert "SSH" not in report.summary_ko
    assert all("SSH" not in item and "격리" not in item for item in report.recommendations)
    assert "별도 확인" in report.summary_ko
    payload = build_waf_slack_payload(report, {"waf_blocked": False})
    assert payload["incident_id"] == report.incident_id
    assert payload["remediation_action"] == "BLOCK_WAF"


@pytest.mark.parametrize("accounts", ["admin", b"admin", [""], [" "], [None]])
def test_web_mapper_rejects_invalid_accounts(accounts: object) -> None:
    """Web 빈 계정 허용이 잘못된 계정 증거 허용으로 확대되지 않도록 검증한다."""
    with pytest.raises(ValueError, match="문자열 목록"):
        map_threat_to_incident(
            is_threat=True,
            rule_name="PATH_TRAVERSAL",
            source_ip="198.51.100.77",
            target_accounts=accounts,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "field,value", [("source_ip", "999.1.1.1"), ("target_identifier", "web-host")]
)
def test_web_mapper_preserves_contract_validation(field: str, value: str) -> None:
    """Web 보고서도 보호된 IPv4·EC2 계약 검증을 그대로 적용한다."""
    with pytest.raises(ValueError):
        map_threat_to_incident(
            is_threat=True,
            rule_name="WEB_DIRECTORY_SCANNING",
            **{
                "source_ip": "198.51.100.77",
                "target_identifier": "i-0123456789abcdef0",
                field: value,
            },
        )


@pytest.mark.parametrize(
    "rule", ["PATH_TRAVERSAL", "SENSITIVE_FILE_PROBING", "WEB_DIRECTORY_SCANNING"]
)
def test_web_mapper_rejects_non_threat_and_uses_web_default_id(rule: str) -> None:
    """비위협은 승격하지 않고 데모 기본 식별자도 SSH 사고와 분리한다."""
    with pytest.raises(ValueError):
        map_threat_to_incident(is_threat=False, rule_name=rule, source_ip="198.51.100.77")
    report = map_threat_to_incident(is_threat=True, rule_name=rule, source_ip="198.51.100.77")
    assert report.incident_id == "INC-SIG-WEB-L7-001"


@pytest.mark.parametrize(
    "rule,attack_type,mitre_id",
    [
        ("PATH_TRAVERSAL", "Web Path Traversal", "T1595.002"),
        ("SENSITIVE_FILE_PROBING", "Web Sensitive File Probing", "T1595.003"),
        ("WEB_DIRECTORY_SCANNING", "Web Directory Scanning", "T1595.003"),
    ],
)
def test_web_mapper_json_output_preserves_exact_contract_fields(
    rule: str, attack_type: str, mitre_id: str
) -> None:
    """세 Web 룰 모두 플랫폼이 소비하는 필드 집합·JSON 타입·WAF 정책을 유지한다.

    Why:
        보호된 계약을 수정하지 않고 보안 매퍼 출력에서 필드 누락이나 추가를 감시한다.
    Side-effects / Edge-cases:
        직렬화 시 튜플은 JSON 배열이 되며 역직렬화 후에도 같은 불변 보고서가 복원되어야 한다.
    """
    report = map_threat_to_incident(
        is_threat=True,
        rule_name=rule,
        source_ip="198.51.100.77",
        target_identifier="i-0123456789abcdef0",
        incident_id="INC-WEB-CONTRACT-001",
    )
    payload = json.loads(report.model_dump_json())
    assert set(payload) == {
        "incident_id",
        "attack_type",
        "mitre_id",
        "risk_level",
        "source_ip",
        "target_identifier",
        "target_accounts",
        "summary_ko",
        "action_required",
        "recommendations",
    }
    assert payload["incident_id"] == "INC-WEB-CONTRACT-001"
    assert payload["attack_type"] == attack_type
    assert payload["mitre_id"] == mitre_id
    assert payload["risk_level"] == "HIGH"
    assert payload["source_ip"] == "198.51.100.77"
    assert payload["target_identifier"] == "i-0123456789abcdef0"
    assert payload["target_accounts"] == []
    assert payload["action_required"] == "BLOCK_WAF"
    assert isinstance(payload["summary_ko"], str) and payload["summary_ko"]
    assert isinstance(payload["recommendations"], list) and payload["recommendations"]
    assert all(isinstance(item, str) and item for item in payload["recommendations"])
    assert IncidentReport.model_validate_json(report.model_dump_json()) == report


@pytest.mark.parametrize(
    "rule", ["PATH_TRAVERSAL", "SENSITIVE_FILE_PROBING", "WEB_DIRECTORY_SCANNING"]
)
def test_web_mapper_output_cannot_be_mutated_to_another_action(rule: str) -> None:
    """후속 소비자가 보안 매퍼의 불변 조치 요청을 현장에서 변조할 수 없다."""
    report = map_threat_to_incident(is_threat=True, rule_name=rule, source_ip="198.51.100.77")
    with pytest.raises(ValidationError, match="frozen_instance"):
        report.action_required = "NONE"
    assert report.action_required == "BLOCK_WAF"


def test_web_mapper_preserves_caller_evidence_and_is_deterministic() -> None:
    """중복 증거 제거는 출력에서만 적용하며 재호출이나 입력 목록을 변조하지 않는다."""
    accounts = ["admin", "root", "admin"]
    kwargs = {
        "is_threat": True,
        "rule_name": "PATH_TRAVERSAL",
        "source_ip": "198.51.100.77",
        "target_accounts": accounts,
        "incident_id": "INC-WEB-EVIDENCE-001",
    }
    first = map_threat_to_incident(**kwargs)
    second = map_threat_to_incident(**kwargs)
    assert first == second
    assert accounts == ["admin", "root", "admin"]
    assert first.target_accounts == ("admin", "root")


@pytest.mark.parametrize("source_ip", ["2001:db8::1", "198.51.100.77/32", "198.51.100.77:443"])
def test_web_mapper_propagates_source_contract_errors(source_ip: str) -> None:
    """잘못된 출발지를 임의 보정하지 않고 계약 예외를 호출부로 전파한다."""
    with pytest.raises(ValidationError, match="source_ip"):
        map_threat_to_incident(is_threat=True, rule_name="PATH_TRAVERSAL", source_ip=source_ip)


@pytest.mark.parametrize("rule", [None, "path_traversal", "UNKNOWN_WEB_RULE"])
def test_web_mapper_does_not_fallback_on_missing_or_unknown_rule(rule: str | None) -> None:
    """누락되거나 미지원인 판정을 WAF 조치로 임의 승격하지 않고 명시적으로 거부한다."""
    with pytest.raises(ValueError):
        map_threat_to_incident(is_threat=True, rule_name=rule, source_ip="198.51.100.77")
