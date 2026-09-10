# CloudShield 단위 테스트: 다중 계층 복합 차단 엔진
# 소유자: 클라우드 A 담당
"""Boto3 다중 계층 차단 엔진(remediation.py) 단위 테스트."""

from __future__ import annotations

import boto3
import pytest

from conftest import MockEc2Target, MockWafTarget
from contracts.incident import IncidentReport
from remediation.remediation import (
    apply_remediation,
    find_quarantine_security_group,
    quarantine_ec2_instance,
)


def test_apply_remediation_interface(sample_incident_report: IncidentReport) -> None:
    """apply_remediation 함수 시그니처 및 반환 타입 스모크 검증.

    Why:
        차단 엔진이 IncidentReport 규격을 정상 수용하고 RemediationResult TypedDict
        규격에 부합하는 계층별 결과를 정상 반환하는지 기본 검증함.
    """
    alert_report = sample_incident_report.model_copy(update={"action_required": "ALERT_ONLY"})
    result = apply_remediation(alert_report)

    assert isinstance(result, dict)
    assert result["waf_blocked"] is False
    assert result["quarantine_applied"] is False
    assert result["iam_revoked"] is False


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


def test_find_quarantine_security_group_success(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """기본 이름(CloudShield-Quarantine-SG)으로 격리 보안 그룹 ID 탐색 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    sg_id = find_quarantine_security_group(ec2_client)

    assert sg_id == mocked_ec2_target.quarantine_sg_id


def test_find_quarantine_security_group_not_found(
    mocked_aws: None,
) -> None:
    """존재하지 않는 보안 그룹 이름 조회 시 None 반환 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    sg_id = find_quarantine_security_group(ec2_client, group_name="NonExistentSG")

    assert sg_id is None


def test_quarantine_ec2_instance_success(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """정상 인스턴스의 기존 보안 그룹이 격리 SG 1개로 원자적 교체되는지 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    # 교체 전: Normal SG 1개 할당 상태
    pre_desc = ec2_client.describe_instances(InstanceIds=[mocked_ec2_target.instance_id])
    pre_sgs = [
        sg["GroupId"] for sg in pre_desc["Reservations"][0]["Instances"][0]["SecurityGroups"]
    ]
    assert pre_sgs == [mocked_ec2_target.normal_sg_id]

    # 격리 조치 실행
    success = quarantine_ec2_instance(
        instance_id=mocked_ec2_target.instance_id,
        ec2_client=ec2_client,
    )
    assert success is True

    # 교체 후: Quarantine SG 1개로 원자적 교체 확인
    post_desc = ec2_client.describe_instances(InstanceIds=[mocked_ec2_target.instance_id])
    post_sgs = [
        sg["GroupId"] for sg in post_desc["Reservations"][0]["Instances"][0]["SecurityGroups"]
    ]
    assert post_sgs == [mocked_ec2_target.quarantine_sg_id]


def test_quarantine_ec2_instance_idempotent(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """이미 격리된 인스턴스에 대한 연속 호출 시 멱등성(Idempotency) 보장 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    # 1차 격리 실행
    first_res = quarantine_ec2_instance(
        instance_id=mocked_ec2_target.instance_id,
        ec2_client=ec2_client,
    )
    assert first_res is True

    # 2차 중복 격리 실행 (동일 결과 및 무오류 보장)
    second_res = quarantine_ec2_instance(
        instance_id=mocked_ec2_target.instance_id,
        ec2_client=ec2_client,
    )
    assert second_res is True

    # 보안 그룹 유지 검증
    desc = ec2_client.describe_instances(InstanceIds=[mocked_ec2_target.instance_id])
    sgs = [sg["GroupId"] for sg in desc["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert sgs == [mocked_ec2_target.quarantine_sg_id]


def test_quarantine_ec2_instance_not_found(
    mocked_aws: None,
) -> None:
    """존재하지 않는 인스턴스 ID 전달 시 ClientError 예외 격리 및 False 반환 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    fake_instance_id = "i-0123456789abcdef0"

    success = quarantine_ec2_instance(
        instance_id=fake_instance_id,
        ec2_client=ec2_client,
    )
    assert success is False


def test_apply_remediation_quarantine_integration(
    mocked_ec2_target: MockEc2Target,
    sample_incident_report: IncidentReport,
) -> None:
    """IncidentReport 기반 apply_remediation 호출 시 L4 격리 성공 검증."""
    # 모의 인프라의 실제 타깃 인스턴스 ID로 리포트 생성
    report = sample_incident_report.model_copy(
        update={
            "target_identifier": mocked_ec2_target.instance_id,
            "action_required": "QUARANTINE_EC2",
        }
    )

    result = apply_remediation(report)

    assert result["quarantine_applied"] is True
    assert result["waf_blocked"] is False
    assert result["iam_revoked"] is False

    # 인스턴스 실제 격리 상태 검증
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    desc = ec2_client.describe_instances(InstanceIds=[mocked_ec2_target.instance_id])
    sgs = [sg["GroupId"] for sg in desc["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert sgs == [mocked_ec2_target.quarantine_sg_id]


def test_apply_remediation_action_routing(
    mocked_ec2_target: MockEc2Target,
    sample_incident_report: IncidentReport,
) -> None:
    """action_required 지시어별 차단 엔진 분기 라우팅 검증."""
    # 1. ALERT_ONLY -> 조치 미실행
    alert_report = sample_incident_report.model_copy(
        update={
            "target_identifier": mocked_ec2_target.instance_id,
            "action_required": "ALERT_ONLY",
        }
    )
    res_alert = apply_remediation(alert_report)
    assert res_alert["quarantine_applied"] is False

    # 2. BLOCK_WAF 단독 -> L4 격리 미실행
    waf_only_report = sample_incident_report.model_copy(
        update={
            "target_identifier": mocked_ec2_target.instance_id,
            "action_required": "BLOCK_WAF",
        }
    )
    res_waf = apply_remediation(waf_only_report)
    assert res_waf["quarantine_applied"] is False


@pytest.mark.skip(reason="클라우드 A 후속 티켓(WAFv2 차단 구현)에서 활성화")
def test_atomic_remediation_success(
    mocked_aws: None,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    sample_incident_report: IncidentReport,
) -> None:
    """moto 가상 환경에서 WAF IP 차단 및 EC2 Quarantine SG 교체 복합 성공 검증."""
    report = sample_incident_report.model_copy(
        update={"target_identifier": mocked_ec2_target.instance_id}
    )
    result = apply_remediation(report)

    assert result["waf_blocked"] is True
    assert result["quarantine_applied"] is True
    assert result["iam_revoked"] is False
