# CloudShield 단위 테스트: 다중 계층 복합 차단 엔진
# 소유자: 클라우드 A 담당
"""Boto3 다중 계층 차단 엔진(remediation.py) 단위 테스트."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import boto3
import pytest

from conftest import MockEc2Target, MockWafTarget
from contracts.events import CloudWatchLogEvent, CloudWatchLogsPayload, NginxAccessLogEvent
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
from remediation.web_window import PersistenceError, WebAttackWindow, parse_nginx_timestamp


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


def _make_cw_nginx_event(
    log_messages: list[str],
    instance_id: str,
    base_timestamp_ms: int = 1727524320000,
    start_idx: int = 0,
) -> dict[str, Any]:
    """Web L7 오케스트레이터 파이프라인 검증용 CloudWatch Logs Nginx 페이로드 생성 헬퍼."""
    events = [
        CloudWatchLogEvent(
            id=f"evt-nginx-{start_idx + idx}",
            timestamp=base_timestamp_ms + (idx * 1000),
            message=msg,
        )
        for idx, msg in enumerate(log_messages)
    ]
    payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream=instance_id,
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=events,
    )
    return {"awslogs": {"data": payload.to_awslogs_data()}}


def test_threat_orchestrator_web_path_traversal(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """Nginx L7 경로 탈출(PATH_TRAVERSAL) 공격 시 WAF IPSet 원자적 차단 및 Slack 전파 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.201"
    messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "GET /../etc/passwd HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True) as mock_send_slack:
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )

        assert res["processed_events"] == 1
        assert res["threats_detected"] == ["PATH_TRAVERSAL"]
        assert len(res["remediation_results"]) == 1
        assert res["remediation_results"][0]["waf_blocked"] is True
        assert res["remediation_results"][0]["quarantine_applied"] is False
        assert res["slack_notified"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]
        mock_send_slack.assert_called_once()
        sent_report = mock_send_slack.call_args.kwargs["report"]
        assert sent_report.action_required == "BLOCK_WAF"
        assert sent_report.attack_type == "Web Path Traversal"


def test_threat_orchestrator_web_sensitive_file_probing(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """Nginx L7 민감 파일 탐색(SENSITIVE_FILE_PROBING) 공격 시 WAF IPSet 원자적 차단 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.202"
    messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "GET /.env HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )

        assert res["processed_events"] == 1
        assert res["threats_detected"] == ["SENSITIVE_FILE_PROBING"]
        assert res["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_threat_orchestrator_web_directory_scanning(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """Nginx L7 디렉터리 스캔(WEB_DIRECTORY_SCANNING) 공격 시 WAF 차단 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.203"
    paths = ["/admin", "/login", "/dashboard", "/api", "/private"]
    statuses = [401, 403, 404, 200, 302]
    messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{idx} +0000] "GET {path} HTTP/1.1" '
            f'{status} 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, (path, status) in enumerate(zip(paths, statuses, strict=True))
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )

        assert res["processed_events"] == 5
        assert res["threats_detected"] == ["WEB_DIRECTORY_SCANNING"]
        assert res["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_threat_orchestrator_web_normal_traffic_no_threat(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """정상 웹 트래픽 인입 시 위협 미탐지 및 차단 생략 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    client_ip = "198.51.100.204"
    messages = [
        (
            f'{client_ip} - - [28/Sep/2026:11:52:00 +0000] "GET /health HTTP/1.1" '
            '200 15 "-" "curl/8.0" 0.001 "-"'
        ),
        (
            f'{client_ip} - - [28/Sep/2026:11:52:01 +0000] "GET /index.html HTTP/1.1" '
            '200 1024 "-" "curl/8.0" 0.002 "-"'
        ),
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert") as mock_send_slack:
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )

        assert res["processed_events"] == 2
        assert res["threats_detected"] == []
        assert res["remediation_results"] == []
        assert res["slack_notified"] is False
        mock_send_slack.assert_not_called()


def test_threat_orchestrator_web_slack_fault_isolation(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """Web L7 WAF 차단 성공 후 Slack Webhook 예외 발생 시 결함 격리(차단 유지) 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.205"
    messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "GET /.env HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch(
        "remediation.orchestrator.send_slack_alert",
        side_effect=RuntimeError("Slack API timeout"),
    ):
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url="https://hooks.slack.com/services/TEST/FAIL",
        )

        assert res["threats_detected"] == ["SENSITIVE_FILE_PROBING"]
        assert res["remediation_results"][0]["waf_blocked"] is True
        assert res["slack_notified"] is False

        # WAF IPSet에는 정상 차단 유지
        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_threat_orchestrator_web_split_batch_window_accumulates(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """분할 배치(3+2)로 인입된 동일 IP 디렉터리 스캔 공격의 슬라이딩 윈도우 관통 차단 검증.

    Why:
        CloudWatch Logs 버퍼링으로 인해 짧은 시간(4초) 내 발생한 스캔 요청이
        복수 Lambda 호출(3개, 2개)로 분할 인입되더라도, 플랫폼 WebAttackWindow를 통해
        호출 간 10초 이력이 누적되어 2차 호출 시점에 원자적 WAF 차단이 정상 집행되는지 검증함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    web_window = WebAttackWindow()

    attacker_ip = "198.51.100.210"
    paths = ["/admin", "/login", "/dashboard", "/api", "/private"]
    statuses = [401, 403, 404, 200, 302]
    all_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{idx} +0000] "GET {path} HTTP/1.1" '
            f'{status} 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, (path, status) in enumerate(zip(paths, statuses, strict=True))
    ]

    # 배치 1: 앞선 3개 요청 인입 (임계치 미달로 미차단)
    event_batch1 = _make_cw_nginx_event(
        all_messages[:3],
        instance_id=mocked_ec2_target.instance_id,
        base_timestamp_ms=1727524320000,
        start_idx=0,
    )
    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res1 = threat_orchestrator_handler(
            event=event_batch1,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=web_window,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )

        assert res1["processed_events"] == 3
        assert res1["threats_detected"] == []
        assert res1["remediation_results"] == []

        ip_set_1 = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" not in ip_set_1["IPSet"]["Addresses"]

        # 배치 2: 후속 2개 요청 인입 (4초 이내 인입되어 3+2 누적 임계치 충족 -> 차단 집행)
        event_batch2 = _make_cw_nginx_event(
            all_messages[3:],
            instance_id=mocked_ec2_target.instance_id,
            base_timestamp_ms=1727524323000,
            start_idx=3,
        )
        res2 = threat_orchestrator_handler(
            event=event_batch2,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=web_window,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )

        assert res2["processed_events"] == 2
        assert res2["threats_detected"] == ["WEB_DIRECTORY_SCANNING"]
        assert len(res2["remediation_results"]) == 1
        assert res2["remediation_results"][0]["waf_blocked"] is True

        ip_set_2 = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set_2["IPSet"]["Addresses"]


def test_threat_orchestrator_web_split_batch_window_expiry_outside_window(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """10초 시간창을 벗어난 요청이 인입될 경우 과거 요청이 만료되어 합산되지 않는지 검증.

    Why:
        10초 이상 간격을 두고 산발적으로 발생하는 정상/비인가 접근이 누적되어
        오탐(False Positive) 및 차단으로 이어지는 문제를 방지하기 위함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    web_window = WebAttackWindow()

    attacker_ip = "198.51.100.211"
    batch1_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{idx} +0000] "GET /{path} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, path in enumerate(["admin", "login", "dashboard"])
    ]
    # 15초 뒤의 2개 요청 (10초 윈도우 초과)
    batch2_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:{15 + idx} +0000] "GET /{path} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, path in enumerate(["api", "private"])
    ]

    event_batch1 = _make_cw_nginx_event(
        batch1_messages,
        instance_id=mocked_ec2_target.instance_id,
        base_timestamp_ms=1727524320000,
        start_idx=0,
    )
    threat_orchestrator_handler(
        event=event_batch1,
        ec2_client=ec2_client,
        waf_client=waf_client,
        web_window=web_window,
    )

    event_batch2 = _make_cw_nginx_event(
        batch2_messages,
        instance_id=mocked_ec2_target.instance_id,
        base_timestamp_ms=1727524335000,
        start_idx=3,
    )
    res2 = threat_orchestrator_handler(
        event=event_batch2,
        ec2_client=ec2_client,
        waf_client=waf_client,
        web_window=web_window,
    )

    # 1차 3개 요청이 만료되어 합산 2개에 불과하므로 임계치 미달로 탐지/차단 미수행
    assert res2["processed_events"] == 2
    assert res2["threats_detected"] == []
    assert res2["remediation_results"] == []

    ip_set = waf_client.get_ip_set(
        Name=mocked_waf_ipset.ipset_name,
        Scope=mocked_waf_ipset.scope,
        Id=mocked_waf_ipset.ipset_id,
    )
    assert f"{attacker_ip}/32" not in ip_set["IPSet"]["Addresses"]


def test_threat_orchestrator_web_oversized_uri_mixed_with_valid_attack_same_ip(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """동일 IP에서 과대 URI(4,096자 초과)와 유효 공격이 혼합 인입될 때 개별 격리 및 차단 검증.

    Why:
        과대 URI에 대한 정규화 예외(ValueError)가 전체 파이프라인을 중단시키지 않고
        개별 격리되어 동일 IP 내 존재하는 다른 유효 공격이 정상 탐지/차단되는지 회귀 검증함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.212"
    oversized_uri = "/test?" + ("a" * 4100)
    messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "GET {oversized_uri} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        ),
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:01 +0000] "GET /.env HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        ),
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )

        assert res["processed_events"] == 2
        assert res["threats_detected"] == ["SENSITIVE_FILE_PROBING"]
        assert len(res["remediation_results"]) == 1
        assert res["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_threat_orchestrator_web_oversized_uri_isolation_preserves_subsequent_ip_threat(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """선행 IP의 과대 URI 오류가 후행 IP의 유효 공격 차단을 중단시키지 않는지 격리 검증.

    Why:
        공격자가 비정상 과대 URI를 고의 주입하여 전체 로그 배치의 차단 엔진을 DoS 시키려는
        시도를 차단하고, 각 출발지 IP별 분석 및 차단 독립성을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    ip_malformed = "198.51.100.213"
    ip_attacker = "198.51.100.214"
    oversized_uri = "/malformed?" + ("x" * 4100)

    messages = [
        (
            f'{ip_malformed} - - [28/Sep/2026:11:52:00 +0000] "GET {oversized_uri} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        ),
        (
            f'{ip_attacker} - - [28/Sep/2026:11:52:01 +0000] "GET /.env HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        ),
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )

        assert res["processed_events"] == 2
        assert res["threats_detected"] == ["SENSITIVE_FILE_PROBING"]
        assert len(res["remediation_results"]) == 1
        assert res["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{ip_attacker}/32" in ip_set["IPSet"]["Addresses"]
        assert f"{ip_malformed}/32" not in ip_set["IPSet"]["Addresses"]


def test_threat_orchestrator_web_split_batch_independent_runtime_shared_dynamodb(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """독립된 2개의 WebAttackWindow 런타임 인스턴스가 공용 DynamoDB를 통해
    3+2 분할 배치를 관통 차단하는지 검증.

    Why:
        복수의 Lambda 동시 실행 환경이나 콜드스타트 환경에서도 개별 인메모리에 의존하지 않고,
        DynamoDB 공유 저장소를 통해 타깃/IP별 10초 이력이 안전하게 영속 집계되어
        2차 배치 수신 런타임에서 원자적 WAF 차단이 정상 집행되는지 회귀 검증함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.220"
    paths = ["admin", "login", "dashboard", "api", "private"]
    all_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{idx} +0000] "GET /{path} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, path in enumerate(paths)
    ]

    # 서로 다른 실행 환경(인스턴스) 모의
    runtime_window_1 = WebAttackWindow()
    runtime_window_2 = WebAttackWindow()

    # 1차 배치: 앞선 3개 요청을 1번 런타임에서 처리 (임계치 미달로 미차단)
    event_batch1 = _make_cw_nginx_event(
        all_messages[:3],
        instance_id=mocked_ec2_target.instance_id,
        base_timestamp_ms=1727524320000,
        start_idx=0,
    )
    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res1 = threat_orchestrator_handler(
            event=event_batch1,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=runtime_window_1,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res1["processed_events"] == 3
        assert res1["threats_detected"] == []
        assert res1["remediation_results"] == []

        # 2차 배치: 후속 2개 요청을 완전히 분리된 2번 런타임에서 처리
        event_batch2 = _make_cw_nginx_event(
            all_messages[3:],
            instance_id=mocked_ec2_target.instance_id,
            base_timestamp_ms=1727524323000,
            start_idx=3,
        )
        res2 = threat_orchestrator_handler(
            event=event_batch2,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=runtime_window_2,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res2["processed_events"] == 2
        assert res2["threats_detected"] == ["WEB_DIRECTORY_SCANNING"]
        assert len(res2["remediation_results"]) == 1
        assert res2["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_threat_orchestrator_web_attack_followed_by_delayed_request_in_single_batch(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """공격 구간(0~4초) 뒤에 시간창 밖 지연 요청(30초)이 혼합 인입되더라도 선행 공격이
    정상 탐지/차단되는지 검증.

    Why:
        배치 내 최신 이벤트 시각 기준으로 유효 시간창 이전 데이터를 평가 전에 일괄 삭제해버리면
        배치 전반부에 발생한 유효한 공격 시퀀스가 유실되는 결함을 방지하고,
        시간순 윈도우 순회 평가를 통해 선행 공격 구간이 정상 차단됨을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.221"
    # 0~4초에 5개의 404 스캔 요청 + 30초에 1개의 404 요청
    messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{idx} +0000] "GET /{path} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, path in enumerate(["admin", "login", "dashboard", "api", "private"])
    ]
    messages.append(
        f'{attacker_ip} - - [28/Sep/2026:11:52:30 +0000] "GET /old HTTP/1.1" '
        '404 150 "-" "curl/8.0" 0.002 "-"'
    )

    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )

        assert res["processed_events"] == 6
        assert res["threats_detected"] == ["WEB_DIRECTORY_SCANNING"]
        assert len(res["remediation_results"]) == 1
        assert res["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_web_attack_window_consistent_read_enforced(mocked_dynamodb_table: Any) -> None:
    """공유 저장소 조회 시 Strongly Consistent Read(ConsistentRead=True)가 호출되는지 검증.

    Why:
        DynamoDB get_item은 기본적으로 Eventual Consistency(최종 일관성)를 사용하므로,
        선행 Lambda 런타임이 기록한 최신 공격 이력이 후속 런타임 조회에 반영되지 않아
        분할 배치가 미탐지로 누락되는 결함을 방지하기 위해 ConsistentRead=True를 강제함.
    """
    window = WebAttackWindow()
    assert window._table is not None

    with patch.object(window._table, "get_item", wraps=window._table.get_item) as mock_get_item:
        window.get_active_events(
            "i-1234567890abcdef0", "198.51.100.220", reference_time=1727524320.0
        )
        assert mock_get_item.call_count >= 1
        for call_args in mock_get_item.call_args_list:
            assert call_args.kwargs.get("ConsistentRead") is True


def test_web_attack_window_init_does_not_call_describe_table(mocked_dynamodb_table: Any) -> None:
    """초기화 시 Table.load()(DescribeTable)를 호출하지 않고 DynamoDB를 즉시 바인딩하는지 검증.

    Why:
        Boto3 Table 리소스는 Lazy 객체이므로 GetItem/UpdateItem 실행 전 사전 메타데이터 로드가
        불필요함. DescribeTable 권한이 없는 IAM 환경에서도 broad except로 인한 조용한
        인메모리 폴백 전이를 차단하고 _use_dynamodb=True가 유지됨을 보장함.
    """
    from botocore.exceptions import ClientError

    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

    with patch.object(
        dynamodb.meta.client,
        "describe_table",
        side_effect=ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "User is not authorized to perform DescribeTable",
                }
            },
            "DescribeTable",
        ),
    ):
        window = WebAttackWindow(dynamodb_resource=dynamodb)
        assert window._use_dynamodb is True
        assert window._table is not None


def test_web_attack_window_split_batch_independent_runtime_with_describe_table_denied(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """DescribeTable 거부 환경에서도 독립 런타임 간 3+2 분할 배치가 정상 누적 탐지/차단되는지 검증.

    Why:
        실제 배포 IAM 역할에 dynamodb:DescribeTable 권한이 없더라도 사전 Table.load() 호출이
        제거되어 인메모리 폴백으로 퇴행하지 않고, 두 번째 Lambda 런타임이 첫 번째 런타임의
        선행 3개 이력을 DynamoDB로부터 강한 일관성으로 읽어내어 관통 차단함을 증명함.
    """
    from botocore.exceptions import ClientError

    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

    attacker_ip = "198.51.100.222"
    paths = ["admin", "login", "dashboard", "api", "private"]
    all_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{idx} +0000] "GET /{path} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, path in enumerate(paths)
    ]

    with patch.object(
        dynamodb.meta.client,
        "describe_table",
        side_effect=ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Access Denied on DescribeTable",
                }
            },
            "DescribeTable",
        ),
    ):
        runtime_window_1 = WebAttackWindow(dynamodb_resource=dynamodb)
        runtime_window_2 = WebAttackWindow(dynamodb_resource=dynamodb)

        assert runtime_window_1._use_dynamodb is True
        assert runtime_window_2._use_dynamodb is True

        event_batch1 = _make_cw_nginx_event(
            all_messages[:3],
            instance_id=mocked_ec2_target.instance_id,
            base_timestamp_ms=1727524320000,
            start_idx=0,
        )
        with patch("remediation.orchestrator.send_slack_alert", return_value=True):
            res1 = threat_orchestrator_handler(
                event=event_batch1,
                ec2_client=ec2_client,
                waf_client=waf_client,
                web_window=runtime_window_1,
                slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
            )
            assert res1["processed_events"] == 3
            assert res1["threats_detected"] == []

            event_batch2 = _make_cw_nginx_event(
                all_messages[3:],
                instance_id=mocked_ec2_target.instance_id,
                base_timestamp_ms=1727524323000,
                start_idx=3,
            )
            res2 = threat_orchestrator_handler(
                event=event_batch2,
                ec2_client=ec2_client,
                waf_client=waf_client,
                web_window=runtime_window_2,
                slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
            )
            assert res2["processed_events"] == 2
            assert res2["threats_detected"] == ["WEB_DIRECTORY_SCANNING"]
            assert len(res2["remediation_results"]) == 1
            assert res2["remediation_results"][0]["waf_blocked"] is True


def test_terraform_lambda_dynamodb_iam_policy_includes_describe_table() -> None:
    """Terraform Lambda IAM 최소 권한 정책에 dynamodb:DescribeTable이 포함되어 있는지 정적 검증.

    Why:
        배포 IAM 정책과 실제 Boto3 SDK 모델 간의 정합성을 보장하여,
        향후 관리 도구나 SDK 호출에서 테이블 상태 조회가 필요할 때 권한 부족 결함이
        발생하지 않도록 방어함.
    """
    from pathlib import Path

    tf_path = Path(__file__).resolve().parents[2] / "infra/terraform/modules/lambda/main.tf"
    content = tf_path.read_text(encoding="utf-8")
    assert "dynamodb:DescribeTable" in content
    assert "dynamodb:GetItem" in content
    assert "dynamodb:PutItem" in content
    assert "dynamodb:UpdateItem" in content
    assert "dynamodb:DeleteItem" in content


def test_terraform_lambda_iam_policy_attachment_references_declared_policy() -> None:
    """Terraform Lambda IAM 정책 첨부 리소스가 선언된 정책 식별자를 참조하는지 회귀 검증.

    Why:
        `aws_iam_role_policy_attachment`에서 존재하지 않는 `aws_iam_policy.least_privilege`를
        참조할 경우 terraform validate 및 배포 시 'Reference to undeclared resource' 치명적 결함이
        발생하므로, 첨부되는 모든 정책 참조가 모듈 내에 실제 선언된 정책 리소스와
        100% 일치함을 HCL 정적 분석으로 보장함.
    """
    import re
    from pathlib import Path

    tf_path = Path(__file__).resolve().parents[2] / "infra/terraform/modules/lambda/main.tf"
    content = tf_path.read_text(encoding="utf-8")

    # 모듈 내 선언된 모든 aws_iam_policy 리소스 이름 수집
    declared_policies = set(re.findall(r'resource\s+"aws_iam_policy"\s+"([^"]+)"', content))
    assert "lambda_least_privilege" in declared_policies

    # aws_iam_role_policy_attachment 리소스에서 참조하는 aws_iam_policy 식별자 수집
    attached_policy_refs = re.findall(r"policy_arn\s*=\s*aws_iam_policy\.([^.]+)\.arn", content)
    assert len(attached_policy_refs) > 0

    for ref in attached_policy_refs:
        err_msg = f"첨부 정책 'aws_iam_policy.{ref}'가 모듈 내에 없음 ({declared_policies})"
        assert ref in declared_policies, err_msg

    # 회귀 검증: 수정 전 잘못된 참조('least_privilege')는 선언 목록에 없어야 함
    assert "least_privilege" not in declared_policies


def test_web_attack_window_expired_history_does_not_block_new_split_batch_attack(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """과거 만료 이력이 누적되어 있더라도 2-버킷 격리로 단일 항목 용량 초과 없이
    신규 3+2 분할 공격이 독립 런타임에서 정상 탐지/차단되는지 검증.

    Why:
        단일 항목에 모든 이벤트를 무제한 append할 경우 400 KB 상한(ValidationException)에
        도달하여 후속 공격 이벤트가 저장 실패 및 미탐지되는 결함을 방지하기 위해,
        10초 시간 버킷 파티셔닝을 통해 만료 이력을 격리하고 신규 공격이
        독립 런타임 간 정상 누적/차단됨을 검증함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.230"
    base_ts = parse_nginx_timestamp("28/Sep/2026:11:52:00 +0000")

    # 1. 34초 전(만료 시간창 밖) 대량의 정상/비인가 요청을 사전 인입
    old_window = WebAttackWindow()
    for idx in range(30):
        sec = 26 + (idx % 30)
        old_msg = (
            f"{attacker_ip} - - [28/Sep/2026:11:51:{sec:02d} +0000] "
            '"GET /health HTTP/1.1" 404 150 "-" "curl/8.0" 0.002 "-"'
        )
        parsed = NginxAccessLogEvent.parse_line(old_msg)
        assert parsed is not None
        added = old_window.add_event(
            target_identifier=mocked_ec2_target.instance_id,
            source_ip=attacker_ip,
            event_id=f"old-evt-{idx}",
            timestamp_epoch=base_ts - 34.0 + (idx * 0.1),
            event=parsed,
        )
        assert added is True

    # 2. 현재 공격 시간창(0~4초)에 동일 IP의 3+2 분할 디렉터리 스캔 공격 인입
    paths = ["admin", "login", "dashboard", "api", "private"]
    attack_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{idx} +0000] "GET /{path} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, path in enumerate(paths)
    ]

    runtime_window_1 = WebAttackWindow()
    runtime_window_2 = WebAttackWindow()

    # 1차 배치 (3개) -> 1번 런타임 (임계치 미달로 미차단)
    event_batch1 = _make_cw_nginx_event(
        attack_messages[:3],
        instance_id=mocked_ec2_target.instance_id,
        base_timestamp_ms=int(base_ts * 1000),
        start_idx=0,
    )
    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res1 = threat_orchestrator_handler(
            event=event_batch1,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=runtime_window_1,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res1["processed_events"] == 3
        assert res1["threats_detected"] == []

        # 2차 배치 (2개) -> 2번 런타임 (2-버킷 모델을 통해 3+2 합산되어 차단 집행)
        event_batch2 = _make_cw_nginx_event(
            attack_messages[3:],
            instance_id=mocked_ec2_target.instance_id,
            base_timestamp_ms=int((base_ts + 3.0) * 1000),
            start_idx=3,
        )
        res2 = threat_orchestrator_handler(
            event=event_batch2,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=runtime_window_2,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res2["processed_events"] == 2
        assert res2["threats_detected"] == ["WEB_DIRECTORY_SCANNING"]
        assert len(res2["remediation_results"]) == 1
        assert res2["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_web_attack_window_current_bucket_saturation_overflow_slot_detection(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """동일 10초 버킷 내 슬롯 0이 400 KB 상한으로 포화되더라도 슬롯 오버플로 청킹을 통해
    독립 런타임 간 3+2 분할 공격이 정상 탐지/차단되는지 검증.

    Why:
        동일 시간 버킷 내 대량의 비위협 요청 인입으로 단일 항목 400 KB 상한(ValidationException)에
        도달하더라도, 슬롯 1로 오버플로 분할 저장되어 후속 공격이 영속화 및 차단됨을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.231"
    base_ts = parse_nginx_timestamp("28/Sep/2026:11:52:00 +0000")

    # 1. 4KB 크기 더미 요청으로 현재 버킷(0초) 슬롯 0을 실제로 400 KB 상한까지 포화
    pad = "a" * 3800
    prep_window = WebAttackWindow()
    for idx in range(110):
        filler_msg = (
            f"{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "
            f'"GET /health?pad={pad}&id={idx} HTTP/1.1" 404 150 "-" "curl/8.0" 0.002 "-"'
        )
        parsed = NginxAccessLogEvent.parse_line(filler_msg)
        assert parsed is not None
        prep_window.add_event(
            target_identifier=mocked_ec2_target.instance_id,
            source_ip=attacker_ip,
            event_id=f"fill-{idx}",
            timestamp_epoch=base_ts,
            event=parsed,
        )

    # 준비 이력과 실제 공격의 시간 버킷이 일치함을 검증
    bucket_id = prep_window._get_bucket_id(base_ts)
    attack_bucket_id = prep_window._get_bucket_id(base_ts + 4.0)
    assert bucket_id == attack_bucket_id

    # 슬롯 0뿐 아니라 오버플로 슬롯 1에도 레코드가 분할 저장되었음을 검증
    slot0_key = prep_window._get_target_key(
        mocked_ec2_target.instance_id, attacker_ip, bucket_id, slot=0
    )
    slot1_key = prep_window._get_target_key(
        mocked_ec2_target.instance_id, attacker_ip, bucket_id, slot=1
    )
    slot0_res = prep_window._table.get_item(Key={"target_key": slot0_key})
    slot1_res = prep_window._table.get_item(Key={"target_key": slot1_key})
    assert "Item" in slot0_res
    assert "Item" in slot1_res

    # 2. 동일 버킷 내 4~8초 시점에 3+2 분할 디렉터리 스캔 공격 인입
    paths = ["admin", "login", "dashboard", "api", "private"]
    attack_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{4 + idx} +0000] "GET /{path} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, path in enumerate(paths)
    ]

    runtime_window_1 = WebAttackWindow()
    runtime_window_2 = WebAttackWindow()

    # 1차 배치 (3개) -> 1번 런타임
    event_batch1 = _make_cw_nginx_event(
        attack_messages[:3],
        instance_id=mocked_ec2_target.instance_id,
        base_timestamp_ms=int((base_ts + 4.0) * 1000),
        start_idx=200,
    )
    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res1 = threat_orchestrator_handler(
            event=event_batch1,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=runtime_window_1,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res1["processed_events"] == 3
        assert res1["threats_detected"] == []

        # 2차 배치 (2개) -> 2번 런타임 (슬롯 0+1 병합으로 3+2 합산되어 차단 집행)
        event_batch2 = _make_cw_nginx_event(
            attack_messages[3:],
            instance_id=mocked_ec2_target.instance_id,
            base_timestamp_ms=int((base_ts + 7.0) * 1000),
            start_idx=203,
        )
        res2 = threat_orchestrator_handler(
            event=event_batch2,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=runtime_window_2,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res2["processed_events"] == 2
        assert res2["threats_detected"] == ["WEB_DIRECTORY_SCANNING"]
        assert len(res2["remediation_results"]) == 1
        assert res2["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_web_attack_window_persistence_error_reported_on_total_exhaustion(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """영속화 오류 시 PersistenceError 함수 오류로 Lambda 재처리/DLQ 트리거 검증.

    Why:
        영속화 실패가 정상 응답 dict로 반환되면 Lambda 비동기 런타임에서 재처리되지 않음.
        핸들러 레벨에서 PersistenceError를 발생시켜 실제 함수 오류 신호 전달을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.232"
    messages = [
        (
            f"{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "
            '"GET /admin HTTP/1.1" 404 150 "-" "curl/8.0" 0.002 "-"'
        )
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    failing_window = WebAttackWindow()
    from botocore.exceptions import ClientError

    with patch.object(
        failing_window._table,
        "update_item",
        side_effect=ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access Denied"}},
            "UpdateItem",
        ),
    ):
        with pytest.raises(PersistenceError) as exc_info:
            threat_orchestrator_handler(
                event=event,
                ec2_client=ec2_client,
                waf_client=waf_client,
                web_window=failing_window,
            )
        assert attacker_ip in str(exc_info.value)


def test_web_orchestrator_write_failure_raises_persistence_error_reprocessing_signal(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """DynamoDB UpdateItem 실패 시 타 IP 처리 지속 및 최종 함수 오류(PersistenceError) 전달 검증.

    Why:
        일부 IP의 쓰기 실패가 발생하더라도 배치의 타 IP 위협 차단은 완결하되,
        미처리 실패가 조용히 무시되지 않고 Lambda 재처리/DLQ를 트리거하는 함수 오류로 반환되어야 함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    failing_ip = "198.51.100.240"
    normal_ip = "198.51.100.241"

    from botocore.exceptions import ClientError

    # failing_ip는 단일 요청, normal_ip는 즉각 차단 대상(경로 탈출)
    messages = [
        (
            f'{failing_ip} - - [28/Sep/2026:11:52:00 +0000] "GET /admin HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        ),
        (
            f'{normal_ip} - - [28/Sep/2026:11:52:01 +0000] "GET /../../etc/passwd HTTP/1.1" '
            '400 150 "-" "curl/8.0" 0.002 "-"'
        ),
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    window = WebAttackWindow()
    original_update = window._table.update_item

    def selective_update(**kwargs: Any) -> Any:
        key = kwargs.get("Key", {}).get("target_key", "")
        if failing_ip in key:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Write Denied"}},
                "UpdateItem",
            )
        return original_update(**kwargs)

    with patch.object(window._table, "update_item", side_effect=selective_update):
        with pytest.raises(PersistenceError) as exc_info:
            threat_orchestrator_handler(
                event=event,
                ec2_client=ec2_client,
                waf_client=waf_client,
                web_window=window,
            )
        assert failing_ip in str(exc_info.value)

    # normal_ip는 함수 오류 전달 전 정상 차단 완료되었음을 검증
    ip_set = waf_client.get_ip_set(
        Name=mocked_waf_ipset.ipset_name,
        Scope=mocked_waf_ipset.scope,
        Id=mocked_waf_ipset.ipset_id,
    )
    assert f"{normal_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_web_orchestrator_read_failure_raises_persistence_error_reprocessing_signal(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """DynamoDB GetItem 조회 실패 시 침해 미탐지 방지 및 함수 오류(PersistenceError) 전달 검증.

    Why:
        테이블에 기존 공격 기록이 있더라도 조회 실패 시 미탐지/조용한 종료로 빠지지 않고,
        Lambda 함수 오류를 전달하여 재시도/DLQ 경로로 인계되도록 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.242"
    from botocore.exceptions import ClientError

    messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "GET /admin HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    window = WebAttackWindow()
    with patch.object(
        window._table,
        "get_item",
        side_effect=ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Read Denied"}},
            "GetItem",
        ),
    ):
        with pytest.raises(PersistenceError) as exc_info:
            threat_orchestrator_handler(
                event=event,
                ec2_client=ec2_client,
                waf_client=waf_client,
                web_window=window,
            )
        assert attacker_ip in str(exc_info.value)


def test_web_orchestrator_all_slots_exhausted_raises_persistence_error_reprocessing_signal(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """모든 슬롯이 400 KB 상한으로 고갈되었을 때 PersistenceError 재처리 신호가 전달되는지 검증.

    Why:
        슬롯 오버플로를 모두 소진한 비정상 포화 시 이벤트를 유실하지 않고 재처리 큐/DLQ로 넘김.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.243"
    from botocore.exceptions import ClientError

    messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "GET /admin HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
    ]
    event = _make_cw_nginx_event(messages, instance_id=mocked_ec2_target.instance_id)

    window = WebAttackWindow()
    with patch.object(
        window._table,
        "update_item",
        side_effect=ClientError(
            {"Error": {"Code": "ValidationException", "Message": "Item size has exceeded 400KB"}},
            "UpdateItem",
        ),
    ):
        with pytest.raises(PersistenceError) as exc_info:
            threat_orchestrator_handler(
                event=event,
                ec2_client=ec2_client,
                waf_client=waf_client,
                web_window=window,
            )
        assert attacker_ip in str(exc_info.value)


def test_web_orchestrator_out_of_order_batches_same_bucket_detected_and_blocked(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """동일 버킷 내에서 후행 이벤트(2~4초, 3건)가 먼저 처리되고 지연된 선행 이벤트(0~1초, 2건)가
    나중에 처리되어도 누적 5건으로 정상 탐지 및 WAF 차단되는지 검증.

    Why:
        비동기 Lambda 동시성 또는 CloudWatch 버퍼링 지연으로 배치 순서가 역전되더라도
        공유 DynamoDB 윈도우에서 최신 시각 기준 10초 슬라이딩 윈도우가 정확히 집계되어야 함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.244"
    base_ts = parse_nginx_timestamp("28/Sep/2026:11:52:00 +0000")

    paths = ["admin", "login", "dashboard", "api", "private"]
    # 0~4초 5개 공격 메시지
    attack_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{idx} +0000] "GET /{path} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, path in enumerate(paths)
    ]

    # 1차 호출: 2~4초의 3건(후행 배치) 먼저 인입
    late_batch = _make_cw_nginx_event(
        attack_messages[2:],
        instance_id=mocked_ec2_target.instance_id,
        base_timestamp_ms=int((base_ts + 2.0) * 1000),
        start_idx=10,
    )
    window_1 = WebAttackWindow()
    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res1 = threat_orchestrator_handler(
            event=late_batch,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=window_1,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res1["processed_events"] == 3
        assert res1["threats_detected"] == []

        # 2차 호출: 0~1초의 2건(선행 배치) 지연 인입 -> 순서 역전 상태에서 3+2 합산 탐지 및 차단
        early_batch = _make_cw_nginx_event(
            attack_messages[:2],
            instance_id=mocked_ec2_target.instance_id,
            base_timestamp_ms=int(base_ts * 1000),
            start_idx=0,
        )
        window_2 = WebAttackWindow()
        res2 = threat_orchestrator_handler(
            event=early_batch,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=window_2,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res2["processed_events"] == 2
        assert res2["threats_detected"] == ["WEB_DIRECTORY_SCANNING"]
        assert len(res2["remediation_results"]) == 1
        assert res2["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_web_orchestrator_out_of_order_batches_bucket_boundary_detected_and_blocked(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """버킷 경계(8~12초)에서 차기 버킷(10~12초, 3건)이 먼저 처리되고 직전 버킷(8~9초, 2건)이
    나중에 처리되어도 3-버킷 조회를 통해 누적 5건으로 정상 탐지 및 WAF 차단되는지 검증.

    Why:
        10초 버킷 경계를 가로지르는 공격에서 후행 버킷이 먼저 처리된 경우라도,
        지연 도착한 직전 버킷 이벤트 처리 시 차기 버킷(cur_bucket + 1)을 조회하고
        최신 시각 기준 10초 윈도우를 평가하여 버킷 경계 순서 역전에서도 완전 탐지해야 함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.245"
    base_ts = parse_nginx_timestamp("28/Sep/2026:11:52:00 +0000")

    paths = ["admin", "login", "dashboard", "api", "private"]
    # 8~9초 2개(버킷 0), 10~12초 3개(버킷 1)
    attack_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:08 +0000] "GET /{paths[0]} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        ),
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:09 +0000] "GET /{paths[1]} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        ),
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:10 +0000] "GET /{paths[2]} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        ),
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:11 +0000] "GET /{paths[3]} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        ),
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:12 +0000] "GET /{paths[4]} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        ),
    ]

    # 1차 호출: 10~12초의 3건 (차기 버킷 1) 먼저 인입
    late_batch = _make_cw_nginx_event(
        attack_messages[2:],
        instance_id=mocked_ec2_target.instance_id,
        base_timestamp_ms=int((base_ts + 10.0) * 1000),
        start_idx=10,
    )
    window_1 = WebAttackWindow()
    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res1 = threat_orchestrator_handler(
            event=late_batch,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=window_1,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res1["processed_events"] == 3
        assert res1["threats_detected"] == []

        # 2차 호출: 8~9초 2건 지연 인입 -> 3-버킷 및 anchor_time 기반으로 5건 탐지/차단
        early_batch = _make_cw_nginx_event(
            attack_messages[:2],
            instance_id=mocked_ec2_target.instance_id,
            base_timestamp_ms=int((base_ts + 8.0) * 1000),
            start_idx=0,
        )
        window_2 = WebAttackWindow()
        res2 = threat_orchestrator_handler(
            event=early_batch,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=window_2,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res2["processed_events"] == 2
        assert res2["threats_detected"] == ["WEB_DIRECTORY_SCANNING"]
        assert len(res2["remediation_results"]) == 1
        assert res2["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_web_orchestrator_delayed_batch_with_subsequent_normal_request_detected_and_blocked(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """후속 정상 요청(15초)이 선행 저장되어 있더라도 지연 도착한 선행 공격(0~1초)이
    유효 10초 구간으로 정상 평가되어 누적 차단되는지 검증.

    Why:
        최신 정상 요청 시각 기준으로 단일 10초 윈도우를 잘라버릴 경우,
        과거에 발생한 유효 공격 시퀀스가 평가 대상에서 누락되는 미탐지 결함을 차단함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.246"
    base_ts = parse_nginx_timestamp("28/Sep/2026:11:52:00 +0000")

    paths = ["admin", "login", "dashboard", "api", "private"]
    # 0~4초 스캔 5개 메시지
    scan_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{idx} +0000] "GET /{path} HTTP/1.1" '
            '404 150 "-" "curl/8.0" 0.002 "-"'
        )
        for idx, path in enumerate(paths)
    ]
    # 15초 정상 요청 메시지
    normal_message = (
        f'{attacker_ip} - - [28/Sep/2026:11:52:15 +0000] "GET /health HTTP/1.1" '
        '200 150 "-" "curl/8.0" 0.002 "-"'
    )

    # 1차 호출: 2~4초 스캔 3건 + 15초 정상 요청 1건 먼저 처리
    first_batch_messages = scan_messages[2:] + [normal_message]
    batch1 = _make_cw_nginx_event(
        first_batch_messages,
        instance_id=mocked_ec2_target.instance_id,
        base_timestamp_ms=int((base_ts + 2.0) * 1000),
        start_idx=10,
    )
    window_1 = WebAttackWindow()
    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res1 = threat_orchestrator_handler(
            event=batch1,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=window_1,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res1["processed_events"] == 4
        assert res1["threats_detected"] == []

        # 2차 호출: 0~1초 스캔 2건 지연 인입 -> 15초 정상 요청이 있어도 0~4초 5건 누적 탐지
        batch2 = _make_cw_nginx_event(
            scan_messages[:2],
            instance_id=mocked_ec2_target.instance_id,
            base_timestamp_ms=int(base_ts * 1000),
            start_idx=0,
        )
        window_2 = WebAttackWindow()
        res2 = threat_orchestrator_handler(
            event=batch2,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=window_2,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res2["processed_events"] == 2
        assert res2["threats_detected"] == ["WEB_DIRECTORY_SCANNING"]
        assert len(res2["remediation_results"]) == 1
        assert res2["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]


def test_web_orchestrator_delayed_single_signature_with_normal_request_blocked(
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
    mocked_dynamodb_table: Any,
) -> None:
    """후속 정상 요청(15초)이 선행 저장되어 있더라도 지연 도착한 단일 시그니처(0초)가
    누락 없이 탐지 및 WAF 차단되는지 검증.

    Why:
        후행 트래픽의 타임스탬프와 관계없이 단일 요청 자체로 위협인 시그니처 이벤트가
        시간 윈도우 필터에 의해 배제되지 않음을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    attacker_ip = "198.51.100.247"
    base_ts = parse_nginx_timestamp("28/Sep/2026:11:52:00 +0000")

    # 15초 정상 요청 메시지
    normal_message = (
        f'{attacker_ip} - - [28/Sep/2026:11:52:15 +0000] "GET /health HTTP/1.1" '
        '200 150 "-" "curl/8.0" 0.002 "-"'
    )
    # 0초 단일 시그니처 공격 메시지
    sensitive_message = (
        f'{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "GET /.env HTTP/1.1" '
        '404 150 "-" "curl/8.0" 0.002 "-"'
    )

    # 1차 호출: 15초 정상 요청 먼저 처리
    batch1 = _make_cw_nginx_event(
        [normal_message],
        instance_id=mocked_ec2_target.instance_id,
        base_timestamp_ms=int((base_ts + 15.0) * 1000),
        start_idx=10,
    )
    window_1 = WebAttackWindow()
    with patch("remediation.orchestrator.send_slack_alert", return_value=True):
        res1 = threat_orchestrator_handler(
            event=batch1,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=window_1,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res1["processed_events"] == 1
        assert res1["threats_detected"] == []

        # 2차 호출: 0초 민감 파일 탐색 지연 인입 -> 15초 정상 요청과 무관하게 탐지/차단
        batch2 = _make_cw_nginx_event(
            [sensitive_message],
            instance_id=mocked_ec2_target.instance_id,
            base_timestamp_ms=int(base_ts * 1000),
            start_idx=0,
        )
        window_2 = WebAttackWindow()
        res2 = threat_orchestrator_handler(
            event=batch2,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=window_2,
            slack_webhook_url="https://hooks.slack.com/services/TEST/WAF/ALERT",
        )
        assert res2["processed_events"] == 1
        assert res2["threats_detected"] == ["SENSITIVE_FILE_PROBING"]
        assert len(res2["remediation_results"]) == 1
        assert res2["remediation_results"][0]["waf_blocked"] is True

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]
