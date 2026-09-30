# CloudShield 단위 테스트: 다중 계층 복합 차단 엔진
# 소유자: 클라우드 A 담당
"""Boto3 다중 계층 차단 엔진(remediation.py) 단위 테스트."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import boto3
import pytest

from conftest import MockEc2Target, MockWafTarget
from contracts.events import CloudWatchLogEvent, CloudWatchLogsPayload
from contracts.incident import IncidentReport
from remediation.auth_window import AuthFailureWindow
from remediation.orchestrator import threat_orchestrator_handler
from remediation.remediation import (
    apply_remediation,
    block_ip_wafv2,
    find_quarantine_security_group,
    find_waf_ip_set,
    quarantine_ec2_instance,
    validate_quarantine_security_group,
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

    # WAF IPSet 실제 차단 상태 검증
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    ip_set = waf_client.get_ip_set(
        Name=mocked_waf_ipset.ipset_name,
        Scope=mocked_waf_ipset.scope,
        Id=mocked_waf_ipset.ipset_id,
    )
    assert f"{sample_incident_report.source_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_validate_quarantine_security_group_success(mocked_ec2_target: MockEc2Target) -> None:
    """인/아웃바운드가 전면 차단된 격리 SG의 유효성 검증 성공 확인."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    is_valid = validate_quarantine_security_group(
        ec2_client=ec2_client,
        sg_id=mocked_ec2_target.quarantine_sg_id,
    )
    assert is_valid is True


def test_validate_quarantine_security_group_fails_with_ingress(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """인바운드 허용 규칙(22/tcp)이 잔존하는 보안 그룹은 격리 SG 검증에서 거부됨을 확인.

    Why:
        관리자 실수나 레거시 설정으로 인바운드가 열려 있는 SG를 격리용으로
        오용할 경우 침해 서버에 대한 추가 공격 인입을 방어할 수 없으므로 유효성 검사에서 차단함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    # 정상 SG(22/tcp 허용)를 검증 대상으로 전달하여 거부 여부 확인
    is_valid = validate_quarantine_security_group(
        ec2_client=ec2_client,
        sg_id=mocked_ec2_target.normal_sg_id,
    )
    assert is_valid is False


def test_validate_quarantine_security_group_fails_with_egress(
    mocked_aws: None,
) -> None:
    """기본 아웃바운드 허용(0.0.0.0/0) 규칙이 남아 있는 보안 그룹은 격리 SG 검증에서 거부됨을 확인.

    Why:
        아웃바운드가 열려 있으면 침해 호스트가 C2 서버로 데이터를 유출하거나
        내부망으로 횡적이동(Lateral Movement)할 수 있으므로 제로 트러스트 요건에 따라 실패 처리함.
    """
    ec2_resource = boto3.resource("ec2", region_name="us-east-1")
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    vpc = ec2_resource.create_vpc(CidrBlock="10.1.0.0/16")
    sg_with_egress = ec2_resource.create_security_group(
        GroupName="SG-With-Default-Egress",
        Description="SG with default outbound rule",
        VpcId=vpc.id,
    )
    # create_security_group 시 기본 아웃바운드(-1, 0.0.0.0/0)가 자동 생성됨
    is_valid = validate_quarantine_security_group(
        ec2_client=ec2_client,
        sg_id=sg_with_egress.id,
    )
    assert is_valid is False


def test_quarantine_ec2_instance_fails_when_sg_policy_invalid(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """허용 규칙(Egress)이 잔존하는 SG로 격리 시도 시 작업 거부 및 기존 SG 유지 검증.

    Why:
        부적합한 보안 그룹으로 인스턴스 속성이 변경되는 것을 방지하고,
        상위 오케스트레이터에 명확히 격리 실패(False)를 반환해야 함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    ec2_resource = boto3.resource("ec2", region_name="us-east-1")

    # 기본 egress가 살아 있는 오염된 격리 SG 생성
    desc = ec2_client.describe_instances(InstanceIds=[mocked_ec2_target.instance_id])
    vpc_id = desc["Reservations"][0]["Instances"][0]["VpcId"]

    invalid_quarantine_sg = ec2_resource.create_security_group(
        GroupName="Invalid-Quarantine-SG",
        Description="Contaminated quarantine SG with default egress",
        VpcId=vpc_id,
    )

    success = quarantine_ec2_instance(
        instance_id=mocked_ec2_target.instance_id,
        ec2_client=ec2_client,
        quarantine_sg_id=invalid_quarantine_sg.id,
    )
    assert success is False

    # 인스턴스 보안 그룹이 변경되지 않고 기존 normal_sg_id로 유지되는지 확인
    post_desc = ec2_client.describe_instances(InstanceIds=[mocked_ec2_target.instance_id])
    current_sgs = [
        sg["GroupId"] for sg in post_desc["Reservations"][0]["Instances"][0]["SecurityGroups"]
    ]
    assert current_sgs == [mocked_ec2_target.normal_sg_id]


def test_quarantine_ec2_instance_fails_when_already_attached_sg_is_contaminated(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """연결된 격리 SG에 사후 인바운드 허용(Ingress)이 추가된 경우 멱등 성공이 아닌 실패 처리 검증.

    Why:
        기존 연결 상태만을 단순 비교하는 멱등성 검사의 맹점을 방어하여,
        SG 규칙이 변조/오염된 경우 성공으로 오판하는 결함을 원천 방지함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    ec2_resource = boto3.resource("ec2", region_name="us-east-1")

    # 1. 1차 정상 격리 수행
    first_res = quarantine_ec2_instance(
        instance_id=mocked_ec2_target.instance_id,
        ec2_client=ec2_client,
    )
    assert first_res is True

    # 2. 할당된 격리 SG에 외부 인바운드 규칙(22/tcp)을 강제 주입하여 오염시킴
    quarantine_sg = ec2_resource.SecurityGroup(mocked_ec2_target.quarantine_sg_id)
    quarantine_sg.authorize_ingress(
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
    )

    # 3. 2차 격리 호출 시 멱등 통과되지 않고 정책 검증 실패(False)가 반환되는지 확인
    second_res = quarantine_ec2_instance(
        instance_id=mocked_ec2_target.instance_id,
        ec2_client=ec2_client,
    )
    assert second_res is False


def test_find_waf_ip_set_success(mocked_waf_ipset: MockWafTarget) -> None:
    """기본 이름(CloudShield-Block-IPSet)으로 WAF IPSet 탐색 검증."""
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    found = find_waf_ip_set(waf_client)

    assert found is not None
    assert found["id"] == mocked_waf_ipset.ipset_id
    assert found["name"] == mocked_waf_ipset.ipset_name
    assert found["arn"] == mocked_waf_ipset.ipset_arn


def test_find_waf_ip_set_not_found(mocked_aws: None) -> None:
    """존재하지 않는 WAF IPSet 이름 조회 시 None 반환 검증."""
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    found = find_waf_ip_set(waf_client, ipset_name="NonExistentIPSet")

    assert found is None


def test_block_ip_wafv2_success(mocked_waf_ipset: MockWafTarget) -> None:
    """단일 IPv4 주소가 /32 CIDR로 WAF IPSet에 원자적 추가되는지 검증."""
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    test_ip = "203.0.113.195"

    success = block_ip_wafv2(
        source_ip=test_ip,
        waf_client=waf_client,
    )
    assert success is True

    # IPSet 상태 검증
    ip_set = waf_client.get_ip_set(
        Name=mocked_waf_ipset.ipset_name,
        Scope=mocked_waf_ipset.scope,
        Id=mocked_waf_ipset.ipset_id,
    )
    assert f"{test_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_block_ip_wafv2_idempotent(mocked_waf_ipset: MockWafTarget) -> None:
    """동일 IP에 대한 연속 호출 시 멱등성(Idempotency) 보장 및 중복 추가 방지 검증."""
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    test_ip = "203.0.113.195"

    first_res = block_ip_wafv2(source_ip=test_ip, waf_client=waf_client)
    assert first_res is True

    second_res = block_ip_wafv2(source_ip=test_ip, waf_client=waf_client)
    assert second_res is True

    ip_set = waf_client.get_ip_set(
        Name=mocked_waf_ipset.ipset_name,
        Scope=mocked_waf_ipset.scope,
        Id=mocked_waf_ipset.ipset_id,
    )
    addresses = ip_set["IPSet"]["Addresses"]
    assert addresses.count(f"{test_ip}/32") == 1


def test_block_ip_wafv2_invalid_ip(mocked_waf_ipset: MockWafTarget) -> None:
    """유효하지 않은 IPv4 주소 인입 시 에러 격리 및 False 반환 검증."""
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    assert block_ip_wafv2(source_ip="999.999.999.999", waf_client=waf_client) is False
    assert block_ip_wafv2(source_ip="not-an-ip", waf_client=waf_client) is False


def test_block_ip_wafv2_non_32_prefix_rejected(mocked_waf_ipset: MockWafTarget) -> None:
    """폭발 반경(Blast Radius) 방지를 위해 /32 이외 서브넷(/24 등) 차단 거부 검증."""
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    assert block_ip_wafv2(source_ip="192.168.1.0/24", waf_client=waf_client) is False


def test_block_ip_wafv2_not_found_ipset(mocked_aws: None) -> None:
    """존재하지 않는 IPSet 대상 차단 시도 시 False 반환 및 ClientError 예외 격리 검증."""
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    success = block_ip_wafv2(
        source_ip="203.0.113.195",
        ipset_name="NonExistentIPSet",
        waf_client=waf_client,
    )
    assert success is False


def test_block_ip_wafv2_optimistic_lock_retry(
    mocked_waf_ipset: MockWafTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """동시 수정 충돌(WAFOptimisticLockException) 발생 시 자동 재시도 후 성공 검증."""
    from botocore.exceptions import ClientError

    waf_client = boto3.client("wafv2", region_name="us-east-1")
    original_update = waf_client.update_ip_set
    call_count = 0

    def mock_update_ip_set(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ClientError(
                error_response={
                    "Error": {
                        "Code": "WAFOptimisticLockException",
                        "Message": "Conflict",
                    }
                },
                operation_name="UpdateIPSet",
            )
        return original_update(**kwargs)

    monkeypatch.setattr(waf_client, "update_ip_set", mock_update_ip_set)

    success = block_ip_wafv2(
        source_ip="203.0.113.196",
        waf_client=waf_client,
    )
    assert success is True
    assert call_count == 2


def test_apply_remediation_waf_action_routing(
    mocked_waf_ipset: MockWafTarget,
    sample_incident_report: IncidentReport,
) -> None:
    """WAF 관련 action_required 지시어별 분기 및 격리 미실행 라우팅 검증."""
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    # 1. BLOCK_WAF 단독
    report_waf = sample_incident_report.model_copy(
        update={"action_required": "BLOCK_WAF", "source_ip": "198.51.100.70"}
    )
    res_waf = apply_remediation(report_waf, waf_client=waf_client)
    assert res_waf["waf_blocked"] is True
    assert res_waf["quarantine_applied"] is False

    # 2. BLOCK_IP_ONLY 단독
    report_ip_only = sample_incident_report.model_copy(
        update={"action_required": "BLOCK_IP_ONLY", "source_ip": "198.51.100.71"}
    )
    res_ip = apply_remediation(report_ip_only, waf_client=waf_client)
    assert res_ip["waf_blocked"] is True
    assert res_ip["quarantine_applied"] is False


def test_block_ip_wafv2_without_description(mocked_aws: None) -> None:
    """설명(Description)이 없는 정상 IPSet에 대해서도 /32 차단 주소가 정상 등록되는지 검증.

    Why:
        AWS WAFv2 UpdateIPSet API에서 Description은 선택 필드이며 최소 길이가 1이므로,
        설명이 정의되지 않은 IPSet에 빈 문자열("")을 전달하여 botocore 유효성 검증 오류
        (ParamValidationError)가 발생하는 결함을 방지함.
    """
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    ipset_name = "NoDesc-IPSet"
    scope = "REGIONAL"

    # Description 필드를 생략하고 IPSet 생성
    create_res = waf_client.create_ip_set(
        Name=ipset_name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=[],
    )
    summary = create_res["Summary"]

    test_ip = "198.51.100.99"
    success = block_ip_wafv2(
        source_ip=test_ip,
        ipset_name=ipset_name,
        ipset_id=summary["Id"],
        scope=scope,
        waf_client=waf_client,
    )
    assert success is True

    # IPSet 상태 검증 (/32 차단 주소 등록 확인)
    ip_set = waf_client.get_ip_set(
        Name=ipset_name,
        Scope=scope,
        Id=summary["Id"],
    )
    assert f"{test_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_find_waf_ip_set_pagination(
    mocked_aws: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """list_ip_sets 응답에 NextMarker가 포함된 다중 페이지 환경에서 대상 IPSet 탐색 및 차단 검증.

    Why:
        WAF IPSet 리소스 수가 많아 결과가 페이지네이션될 때, 첫 페이지에 대상이 없더라도
        NextMarker를 따라 후속 페이지까지 완전 순회하여 정상 리소스를 누락 없이 식별해야 함.
    """
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    scope = "REGIONAL"
    target_ipset_name = "Page2-Target-IPSet"

    # 실제 moto IPSet 1개 생성 (Page 2에서 반환할 실제 객체)
    create_res = waf_client.create_ip_set(
        Name=target_ipset_name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=[],
        Description="Target IPSet on Page 2",
    )
    real_summary = create_res["Summary"]

    # list_ip_sets 응답을 2페이지로 가상화 (1페이지: 더미 + NextMarker, 2페이지: 실제 타깃)
    original_list_ip_sets = waf_client.list_ip_sets

    def mock_list_ip_sets(**kwargs: Any) -> dict[str, Any]:
        marker = kwargs.get("NextMarker")
        if not marker:
            return {
                "NextMarker": "marker-page-2",
                "IPSets": [
                    {
                        "Name": "Dummy-IPSet-Page-1",
                        "Id": "dummy-id-1",
                        "ARN": (
                            "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/Dummy-1/dummy-id-1"
                        ),
                        "LockToken": "dummy-token-1",
                    }
                ],
            }
        if marker == "marker-page-2":
            return {
                "IPSets": [
                    {
                        "Name": real_summary["Name"],
                        "Id": real_summary["Id"],
                        "ARN": real_summary["ARN"],
                        "LockToken": real_summary["LockToken"],
                    }
                ],
            }
        return original_list_ip_sets(**kwargs)

    monkeypatch.setattr(waf_client, "list_ip_sets", mock_list_ip_sets)

    # 1. find_waf_ip_set 다중 페이지 탐색 검증
    found = find_waf_ip_set(waf_client=waf_client, ipset_name=target_ipset_name, scope=scope)
    assert found is not None
    assert found["name"] == target_ipset_name
    assert found["id"] == real_summary["Id"]

    # 2. 이름 기반 차단(block_ip_wafv2)에서도 2페이지 대상을 정상 탐색하여 차단 성공하는지 검증
    test_ip = "198.51.100.123"
    success = block_ip_wafv2(
        source_ip=test_ip,
        ipset_name=target_ipset_name,
        scope=scope,
        waf_client=waf_client,
    )
    assert success is True

    # 실제 WAF IPSet에 반영되었는지 확인
    ip_set = waf_client.get_ip_set(
        Name=target_ipset_name,
        Scope=scope,
        Id=real_summary["Id"],
    )
    assert f"{test_ip}/32" in ip_set["IPSet"]["Addresses"]


# ==============================================================================
# 3. 오케스트레이터 - Slack 알림 연동 및 통합 차단 파이프라인 결합 테스트
# ==============================================================================


def _make_cw_auth_event(
    log_messages: list[str],
    instance_id: str,
    base_timestamp_ms: int = 1725433265000,
) -> dict[str, Any]:
    """오케스트레이터 파이프라인 검증용 CloudWatch Logs 구독 필터 페이로드 생성 헬퍼.

    Why:
        CloudWatch Logs Subscription Filter에서 인입되는 Base64 Gzip 인코딩 구조를
        표준 규격대로 가상화하여 Lambda 핸들러의 디코딩 및 파싱 단계를 검증함.
    """
    events = [
        CloudWatchLogEvent(
            id=f"evt-{idx}",
            timestamp=base_timestamp_ms + (idx * 1000),
            message=msg,
        )
        for idx, msg in enumerate(log_messages)
    ]
    payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/auth-log",
        logStream=instance_id,
        subscriptionFilters=["CloudShield-FailedPassword-Filter"],
        logEvents=events,
    )
    return {"awslogs": {"data": payload.to_awslogs_data()}}


def test_threat_orchestrator_slack_integration_success(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """위협 탐지 및 인프라 차단 완료 후 Slack Block Kit 알림이 성공적으로 전파되는지 검증.

    Why:
        10초 관통 파이프라인의 종단 단계로서, L4 SG 격리 및 L7 WAF 차단 성공 결과가
        SecOps 관리자 채널에 실시간 Slack 카드로 전파되고 slack_notified=True가 반환됨을 보장함.

    Constraints:
        - 5회 이상 실패 로그 인입으로 SSH_BRUTE_FORCE 위협 발생.
        - send_slack_alert 호출 시 IncidentReport 및 RemediationResult가 함께 전달되어야 함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    attacker_ip = "198.51.100.99"
    target_user = "admin"
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/TEST_SUCCESS"

    messages = [
        (
            f"Sep 04 15:01:0{i} target-ec2 sshd[2110{i}]: Failed password for "
            f"{target_user} from {attacker_ip} port 4120{i} ssh2"
        )
        for i in range(1, 6)
    ]
    event = _make_cw_auth_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True) as mock_send_slack:
        res = threat_orchestrator_handler(
            event=event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url=dummy_webhook,
        )

        assert res["processed_events"] == 5
        assert res["threats_detected"] == ["SSH_BRUTE_FORCE"]
        assert len(res["remediation_results"]) == 1
        assert res["remediation_results"][0]["quarantine_applied"] is True
        assert res["remediation_results"][0]["waf_blocked"] is True
        assert res["slack_notified"] is True

        mock_send_slack.assert_called_once()
        call_kwargs = mock_send_slack.call_args.kwargs
        assert call_kwargs["webhook_url"] == dummy_webhook
        assert call_kwargs["report"].incident_id.startswith("INC-")
        assert call_kwargs["report"].attack_type == "SSH Brute Force"
        assert call_kwargs["report"].mitre_id == "T1110.001"
        assert call_kwargs["report"].risk_level == "HIGH"
        assert call_kwargs["report"].action_required == "BLOCK_AND_QUARANTINE"
        assert call_kwargs["report"].source_ip == attacker_ip
        assert call_kwargs["report"].target_identifier == mocked_ec2_target.instance_id
        assert call_kwargs["report"].target_accounts == (target_user,)
        assert call_kwargs["remediation_result"]["quarantine_applied"] is True
        assert call_kwargs["remediation_result"]["waf_blocked"] is True


def test_threat_orchestrator_password_spraying_mapper_integration(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """Password Spraying 공격 탐지 시 보안 매퍼 연동 및 L7 WAF 전용 차단 검증.

    Why:
        오케스트레이터가 하드코딩된 보고서 생성을 탈피하고 보안 매퍼와 결합할 때,
        SSH_PASSWORD_SPRAYING 위협에 대해 MITRE T1110.003, MEDIUM 위험도, BLOCK_IP_ONLY 조치 지시가
        정상 반영되어 EC2 격리(L4)는 건너뛰고 WAF IP 차단(L7)만 원자적으로 집행되는지 검증함.

    Constraints:
        - 동일 IP에서 2개 이상의 상이한 사용자 계정 실패 발생 시 탐지.
        - action_required가 BLOCK_IP_ONLY이므로 quarantine_applied는 False,
          waf_blocked는 True여야 함.
        - DynamoDB에 격리 완료 플래그가 정상 마킹되어야 함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    attacker_ip = "198.51.100.105"
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/SPRAY_SUCCESS"

    messages = [
        (
            f"Sep 04 15:06:01 target-ec2 sshd[26101]: Failed password for "
            f"user_alice from {attacker_ip} port 51101 ssh2"
        ),
        (
            f"Sep 04 15:06:02 target-ec2 sshd[26102]: Failed password for "
            f"user_bob from {attacker_ip} port 51102 ssh2"
        ),
    ]
    event = _make_cw_auth_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True) as mock_send_slack:
        res = threat_orchestrator_handler(
            event=event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url=dummy_webhook,
        )

        assert res["processed_events"] == 2
        assert res["threats_detected"] == ["SSH_PASSWORD_SPRAYING"]
        assert len(res["remediation_results"]) == 1
        # BLOCK_IP_ONLY 이므로 L4 격리는 False, L7 WAF는 True
        assert res["remediation_results"][0]["quarantine_applied"] is False
        assert res["remediation_results"][0]["waf_blocked"] is True
        assert res["slack_notified"] is True

        # EC2 보안 그룹 변경 없어야 함 (정상 SG 유지)
        desc = ec2_client.describe_instances(InstanceIds=[mocked_ec2_target.instance_id])
        current_sgs = [
            sg["GroupId"] for sg in desc["Reservations"][0]["Instances"][0]["SecurityGroups"]
        ]
        assert current_sgs == [mocked_ec2_target.normal_sg_id]

        # WAF IPSet에는 등록되어야 함
        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]

        # 보안 매퍼로부터 생성된 리포트 정합성 검증
        mock_send_slack.assert_called_once()
        report = mock_send_slack.call_args.kwargs["report"]
        assert report.attack_type == "SSH Password Spraying"
        assert report.mitre_id == "T1110.003"
        assert report.risk_level == "MEDIUM"
        assert report.action_required == "BLOCK_IP_ONLY"
        assert report.source_ip == attacker_ip
        assert report.target_identifier == mocked_ec2_target.instance_id


def test_threat_orchestrator_slack_failure_fault_isolation(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """Slack Webhook 호출 실패/예외 발생 시에도 L4/L7 차단 및 마킹이 롤백되지 않고 유지되는지 검증.

    Why:
        Slack API 서비스 장애, 네트워크 타임아웃(3초 초과) 또는 5xx 오류가 발생하더라도
        사전에 집행된 원자적 인프라 격리(SG 전면 차단 / WAF IPSet 등록) 상태는 무조건
        유지되어야 하며, 파이프라인 전체가 Crash되거나 차단이 취소되는 보안 사고를 원천 차단함.

    Side-effects / Edge-cases:
        - send_slack_alert에서 런타임 예외(RuntimeError) 발생 모의.
        - slack_notified=False가 안전하게 반환되고, 인스턴스는 여전히 격리 SG 상태를 유지해야 함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    attacker_ip = "198.51.100.101"
    target_user = "root"
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/TEST_FAIL"

    messages = [
        (
            f"Sep 04 15:02:0{i} target-ec2 sshd[2210{i}]: Failed password for "
            f"{target_user} from {attacker_ip} port 4220{i} ssh2"
        )
        for i in range(1, 6)
    ]
    event = _make_cw_auth_event(messages, instance_id=mocked_ec2_target.instance_id)

    # Slack 알림 호출 시 예외가 발생하는 상황 시뮬레이션
    with patch(
        "remediation.orchestrator.send_slack_alert",
        side_effect=RuntimeError("Slack Webhook timeout (3.0s limit exceeded)"),
    ):
        res = threat_orchestrator_handler(
            event=event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url=dummy_webhook,
        )

        # 1. 알림 전파 결과는 실패(False)로 격리 반환
        assert res["slack_notified"] is False
        assert res["threats_detected"] == ["SSH_BRUTE_FORCE"]
        assert len(res["remediation_results"]) == 1

        # 2. L4 격리 및 L7 WAF 차단 결과는 정상 집행 상태(True) 유지 확인
        assert res["remediation_results"][0]["quarantine_applied"] is True
        assert res["remediation_results"][0]["waf_blocked"] is True

        # 3. 실제 EC2 보안 그룹이 격리 SG로 교체된 상태 유지 확인 (롤백 없음)
        desc = ec2_client.describe_instances(InstanceIds=[mocked_ec2_target.instance_id])
        current_sgs = [
            sg["GroupId"] for sg in desc["Reservations"][0]["Instances"][0]["SecurityGroups"]
        ]
        assert current_sgs == [mocked_ec2_target.quarantine_sg_id]

        # 4. 실제 WAF IPSet에 차단 주소 등록 상태 유지 확인 (롤백 없음)
        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]

        # 5. DynamoDB 격리 완료 마킹 상태 유지 확인 (차기 이벤트 재시도 억제)
        is_threat_again, _, _ = auth_window.check_threat(attacker_ip, target_user)
        assert is_threat_again is False


def test_threat_orchestrator_slack_no_webhook_url(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SLACK_WEBHOOK_URL이 설정되지 않은 환경에서도 차단 파이프라인이 정상 완료되는지 검증.

    Why:
        Webhook URL 환경 변수가 미설정된 스테이징/개발 환경에서도 차단 엔진이
        중단 없이 실행되고, slack_notified=False로 안전하게 종료됨을 보장함.
    """
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)

    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    attacker_ip = "198.51.100.102"
    target_user = "admin"

    messages = [
        (
            f"Sep 04 15:03:0{i} target-ec2 sshd[2310{i}]: Failed password for "
            f"{target_user} from {attacker_ip} port 4320{i} ssh2"
        )
        for i in range(1, 6)
    ]
    event = _make_cw_auth_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert") as mock_send_slack:
        res = threat_orchestrator_handler(
            event=event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url=None,
        )

        assert res["threats_detected"] == ["SSH_BRUTE_FORCE"]
        assert res["remediation_results"][0]["quarantine_applied"] is True
        assert res["remediation_results"][0]["waf_blocked"] is True
        assert res["slack_notified"] is False
        mock_send_slack.assert_not_called()


def test_threat_orchestrator_slack_no_threat_defaults_to_false(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """위협이 탐지되지 않는 정상/소량 실패 이벤트 인입 시 slack_notified=False 유지 검증.

    Why:
        임계치에 도달하지 않은 일상 로그 배치에서는 불필요한 알림 발송을 억제하고
        기본 slack_notified 상태가 False로 일관되게 반환되어야 함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    messages = [
        (
            "Sep 04 15:04:01 target-ec2 sshd[24101]: Failed password for "
            "user from 198.51.100.103 port 1111 ssh2"
        ),
        (
            "Sep 04 15:04:02 target-ec2 sshd[24102]: Failed password for "
            "user from 198.51.100.103 port 1112 ssh2"
        ),
    ]
    event = _make_cw_auth_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert") as mock_send_slack:
        res = threat_orchestrator_handler(
            event=event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url="https://hooks.slack.com/services/T000/B000/TEST",
        )

        assert res["processed_events"] == 2
        assert res["threats_detected"] == []
        assert res["remediation_results"] == []
        assert res["slack_notified"] is False
        mock_send_slack.assert_not_called()


def test_threat_orchestrator_slack_env_var_fallback(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """함수 파라미터가 None일 때 환경 변수 SLACK_WEBHOOK_URL을 정상 참조하여 발송하는지 검증."""
    env_webhook = "https://hooks.slack.com/services/ENV/FALLBACK/URL"
    monkeypatch.setenv("SLACK_WEBHOOK_URL", env_webhook)

    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    messages = [
        (
            f"Sep 04 15:05:0{i} target-ec2 sshd[2510{i}]: Failed password for "
            f"testuser from 198.51.100.104 port 4520{i} ssh2"
        )
        for i in range(1, 6)
    ]
    event = _make_cw_auth_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True) as mock_send_slack:
        res = threat_orchestrator_handler(
            event=event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url=None,  # 명시적 None 전달
        )

        assert res["slack_notified"] is True
        mock_send_slack.assert_called_once()
        assert mock_send_slack.call_args.kwargs["webhook_url"] == env_webhook
