# CloudShield 단위 테스트: 다중 계층 복합 차단 엔진
# 소유자: 클라우드 A 담당
"""Boto3 다중 계층 차단 엔진(remediation.py) 단위 테스트."""

from __future__ import annotations

import pytest

from conftest import MockEc2Target, MockWafTarget
from contracts.incident import IncidentReport
from remediation.remediation import apply_remediation


def test_apply_remediation_interface(sample_incident_report: IncidentReport) -> None:
    """apply_remediation 함수 시그니처 및 스켈레톤 인터페이스 스모크 검증.

    Why:
        클라우드 A 담당 에이전트가 remediation.py 구현 착수 전 모듈 import 경로와
        함수 시그니처(IncidentReport 인자 수락 여부)를 즉각 검증함.
    """
    with pytest.raises(NotImplementedError, match="클라우드 A 담당자 구현 영역"):
        apply_remediation(sample_incident_report)


def test_mocked_aws_fixtures_provisioning(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """moto 가상 AWS 리소스(EC2, SG, WAF IPSet)가 정상 프로비저닝되었는지 검증."""
    assert mocked_ec2_target.instance_id.startswith("i-")
    assert mocked_ec2_target.normal_sg_id.startswith("sg-")
    assert mocked_ec2_target.quarantine_sg_id.startswith("sg-")
    assert mocked_waf_ipset.scope == "REGIONAL"
    assert len(mocked_waf_ipset.ipset_id) >= 1


@pytest.mark.skip(reason="클라우드 A 구현 대기")
def test_atomic_remediation_success(
    mocked_aws: None,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    sample_incident_report: IncidentReport,
) -> None:
    """moto 가상 환경에서 WAF IP 차단 및 EC2 Quarantine SG 교체 성공 검증."""
    result = apply_remediation(sample_incident_report)

    assert result["waf_blocked"] is True
    assert result["quarantine_applied"] is True
    assert result["iam_revoked"] is False
