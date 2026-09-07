# CloudShield 테스트베드 공통 Fixture
# 소유자: 클라우드 A (플랫폼 & 테스트 하네스)
"""pytest 공통 픽스처 모음.

Why:
    팀원들이 AWS 실제 콘솔 연결이나 과금 걱정 없이 로컬에서 모듈을 격리 개발할 수 있도록
    표준 모의 데이터셋 로더 및 moto 기반의 가상 AWS 인프라 리소스 픽스처를 제공함.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path
from typing import Any, NamedTuple

import boto3
import pytest
from moto import mock_aws

from contracts.incident import IncidentReport

MOCK_DATA_DIR = Path(__file__).parent / "mock_data"


class MockEc2Target(NamedTuple):
    """테스트용 가상 EC2 타깃 및 보안 그룹 식별자 튜플."""

    instance_id: str
    normal_sg_id: str
    quarantine_sg_id: str


class MockWafTarget(NamedTuple):
    """테스트용 가상 WAFv2 IPSet 식별자 튜플."""

    ipset_id: str
    ipset_arn: str
    ipset_name: str
    scope: str


# ==============================================================================
# 1. Mock Data Fixtures
# ==============================================================================


@pytest.fixture
def sample_auth_log_lines() -> list[str]:
    """tests/mock_data/mock_auth.log 원문 라인 리스트 반환."""
    log_file = MOCK_DATA_DIR / "mock_auth.log"
    return [
        line.strip() for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()
    ]


@pytest.fixture
def sample_cw_event() -> dict[str, Any]:
    """tests/mock_data/mock_cw_event.json Lambda 인입 이벤트 딕셔너리 반환."""
    event_file = MOCK_DATA_DIR / "mock_cw_event.json"
    return json.loads(event_file.read_text(encoding="utf-8"))


@pytest.fixture
def sample_incident_data() -> dict[str, Any]:
    """tests/mock_data/mock_incident.json 원본 딕셔너리 반환."""
    incident_file = MOCK_DATA_DIR / "mock_incident.json"
    return json.loads(incident_file.read_text(encoding="utf-8"))


@pytest.fixture
def sample_incident_report(sample_incident_data: dict[str, Any]) -> IncidentReport:
    """tests/mock_data/mock_incident.json 역직렬화 IncidentReport 인스턴스 반환."""
    return IncidentReport.model_validate(sample_incident_data)


# ==============================================================================
# 2. moto 기반 가상 AWS Fixtures
# ==============================================================================


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """실제 AWS API 호출 누출 방지 및 테스트용 더미 자격증명 강제 설정.

    Why:
        개발자 로컬 환경의 ~/.aws/credentials 또는 환경변수에 실제 AWS 키가 있더라도
        테스트 런타임에는 더미 키를 강제 주입하여 실제 인프라 호출을 원천 차단함.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def mocked_aws() -> Generator[None, None, None]:
    """moto.mock_aws 컨텍스트를 활성화하여 실제 AWS API 호출을 원천 차단."""
    with mock_aws():
        yield


@pytest.fixture
def mocked_ec2_target(mocked_aws: None) -> MockEc2Target:
    """moto 가상 VPC 내 타깃 EC2 1대 및 Normal SG, Quarantine SG 사전 생성.

    Why:
        L4 보안 그룹 격리(apply_remediation) 테스트 시 실제 EC2 리소스 없이도
        보안 그룹 교체(ModifyInstanceAttribute)를 검증할 수 있는 테스트베드 제공.
    """
    ec2_resource = boto3.resource("ec2", region_name="us-east-1")

    # VPC 및 서브넷 프로비저닝
    vpc = ec2_resource.create_vpc(CidrBlock="10.0.0.0/16")
    subnet = ec2_resource.create_subnet(VpcId=vpc.id, CidrBlock="10.0.1.0/24")

    # Normal Security Group (SSH 22 허용)
    normal_sg = ec2_resource.create_security_group(
        GroupName="TargetNormalSG",
        Description="Normal EC2 Security Group",
        VpcId=vpc.id,
    )
    normal_sg.authorize_ingress(
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ]
    )

    # Quarantine Security Group (격리용 인바운드 미허용 SG)
    quarantine_sg = ec2_resource.create_security_group(
        GroupName="CloudShield-Quarantine-SG",
        Description="Zero-trust isolation SG with no ingress",
        VpcId=vpc.id,
    )

    # 타깃 EC2 인스턴스 생성
    instances = ec2_resource.create_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SubnetId=subnet.id,
        SecurityGroupIds=[normal_sg.id],
    )
    target_instance = instances[0]

    return MockEc2Target(
        instance_id=target_instance.id,
        normal_sg_id=normal_sg.id,
        quarantine_sg_id=quarantine_sg.id,
    )


@pytest.fixture
def mocked_waf_ipset(mocked_aws: None) -> MockWafTarget:
    """moto 가상 WAFv2 IPSet 사전 생성.

    Why:
        L7 공격자 IP 인바운드 차단(apply_remediation) 테스트 시 WAF IPSet에
        공격자 IP(/32)가 성공적으로 추가되는지 검증하기 위한 가상 리소스 제공.
    """
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    ipset_name = "CloudShield-Block-IPSet"
    scope = "REGIONAL"

    response = waf_client.create_ip_set(
        Name=ipset_name,
        Scope=scope,
        IPAddressVersion="IPV4",
        Addresses=[],
        Description="CloudShield Automated Remediation Blocked IPSet",
    )
    summary = response["Summary"]
    return MockWafTarget(
        ipset_id=summary["Id"],
        ipset_arn=summary["ARN"],
        ipset_name=summary["Name"],
        scope=scope,
    )
