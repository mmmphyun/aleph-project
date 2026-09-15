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
