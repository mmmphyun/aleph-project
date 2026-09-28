# CloudShield 단위 테스트: 결정론적 침해사고 매퍼
# 소유자: 보안 담당
"""결정론적 침해사고 매퍼(incident_mapper.py) 단위 테스트."""

from __future__ import annotations

import pytest

from contracts.incident import IncidentReport
from detection.incident_mapper import analyze_incident, map_threat_to_incident


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
