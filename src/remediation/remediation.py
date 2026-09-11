# CloudShield 차단 엔진: 다중 계층 복합 대응
# 소유자: 클라우드 A 담당
"""Boto3 기반 다중 계층(L4 SG / L7 WAF / IAM 세션) 원자적 차단 엔진.

Why:
    IncidentReport의 대응 지시(action_required)에 따라 침해 인스턴스 격리(L4),
    공격자 IP 인바운드 차단(L7), 탈취 의심 IAM 임시 세션 무효화(Identity)를
    자동 수행하여 사고 확산을 방지함.

Constraints:
    - Boto3 Client 호출 시 멱등성(Idempotency)을 보장해야 함 (중복 호출 시 에러 미발생).
    - IP 차단 시 단일 IPv4 주소는 반드시 CIDR /32 규격으로 변환되어야 함.
"""

from __future__ import annotations

import logging
import os
from typing import Any, TypedDict

import boto3
from botocore.exceptions import ClientError

from contracts.incident import IncidentReport

logger = logging.getLogger(__name__)

DEFAULT_QUARANTINE_SG_NAME = "CloudShield-Quarantine-SG"


class RemediationResult(TypedDict):
    """AWS 다중 계층 원자적 차단 실행 결과 모델.

    Why:
        클라우드 A(차단 엔진)와 클라우드 B(Slack 알림 카드) 간에
        딕셔너리 키 이름 불일치(KeyError)로 인한 런타임 결합 실패를 원천 방지함.
    """

    waf_blocked: bool
    quarantine_applied: bool
    iam_revoked: bool


def find_quarantine_security_group(
    ec2_client: Any,
    vpc_id: str | None = None,
    group_name: str = DEFAULT_QUARANTINE_SG_NAME,
) -> str | None:
    """격리용 보안 그룹(CloudShield-Quarantine-SG)의 GroupId를 조회.

    Why:
        인프라 환경에 따라 미리 생성된 격리 보안 그룹의 ID가 동적으로 변경될 수 있으므로,
        표준 네이밍 규약에 따라 해당 VPC 내의 격리 SG를 탐색하여 결합도를 낮춤.

    Constraints:
        - group_name: 조회 대상 격리 보안 그룹명 (기본값: CloudShield-Quarantine-SG).
        - 반환값: 탐색 성공 시 'sg-xxxx' 문자열, 미발견 시 None.

    Side-effects / Edge-cases:
        - AWS API 호출 실패(ClientError) 시 에러를 전파하지 않고 None을 반환하여
          차단 엔진의 예외 격리 원칙을 준수함.
    """
    filters: list[dict[str, Any]] = [{"Name": "group-name", "Values": [group_name]}]
    if vpc_id:
        filters.append({"Name": "vpc-id", "Values": [vpc_id]})

    try:
        response = ec2_client.describe_security_groups(Filters=filters)
        security_groups = response.get("SecurityGroups", [])
        if not security_groups:
            logger.warning("격리 보안 그룹 탐색 실패: group_name=%s, vpc_id=%s", group_name, vpc_id)
            return None
        return str(security_groups[0]["GroupId"])
    except ClientError as e:
        logger.error("격리 보안 그룹 조회 중 AWS ClientError 발생: %s", e)
        return None


def quarantine_ec2_instance(
    instance_id: str,
    ec2_client: Any = None,
    quarantine_sg_id: str | None = None,
    quarantine_sg_name: str = DEFAULT_QUARANTINE_SG_NAME,
) -> bool:
    """침해 타깃 EC2의 보안 그룹을 격리 보안 그룹으로 원자적 교체.

    Why:
        침해 사고 발생 시 모든 허용 보안 그룹을 단일 격리 SG(인바운드 전면 차단)로
        즉시 원자적 교체(modify_instance_attribute)하여 내부망 전파를 원천 차단함.

    Constraints:
        - instance_id: 'i-' 접두사로 시작하는 유효한 AWS EC2 인스턴스 ID.
        - quarantine_sg_id가 주어지지 않은 경우 quarantine_sg_name으로 자동 탐색함.

    Side-effects / Edge-cases:
        - 이미 격리 SG 단독 적용 상태인 경우 중복 API 호출 없이 즉시 True 반환 (멱등성).
        - 유효하지 않은 인스턴스 ID, 인스턴스 미존재, 권한 부족 등의 ClientError 발생 시
          False를 반환하고 상위 파이프라인의 중단을 방지함.
    """
    if ec2_client is None:
        region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        ec2_client = boto3.client("ec2", region_name=region)

    try:
        # 1. 대상 인스턴스 상태 및 VPC, 현재 연결된 보안 그룹 조회
        desc_res = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = desc_res.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            logger.error("격리 대상 인스턴스를 찾을 수 없음: %s", instance_id)
            return False

        target_instance = reservations[0]["Instances"][0]
        vpc_id = target_instance.get("VpcId")
        current_sgs = [sg["GroupId"] for sg in target_instance.get("SecurityGroups", [])]

        # 2. 격리 보안 그룹 ID 확정
        target_sg_id = quarantine_sg_id
        if not target_sg_id:
            target_sg_id = find_quarantine_security_group(
                ec2_client, vpc_id=vpc_id, group_name=quarantine_sg_name
            )

        if not target_sg_id:
            logger.error(
                "인스턴스 %s 격리에 필요한 보안 그룹(%s)을 찾을 수 없음",
                instance_id,
                quarantine_sg_name,
            )
            return False

        # 3. 멱등성 검사: 이미 격리 SG 단독 적용 상태인지 확인
        if current_sgs == [target_sg_id]:
            logger.info(
                "인스턴스 %s는 이미 격리 보안 그룹(%s)에 배치되어 있음 (멱등 처리)",
                instance_id,
                target_sg_id,
            )
            return True

        # 4. 원자적 보안 그룹 전면 교체 (기존 보안 그룹 목록을 격리 SG 1개로 단독 대체)
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[target_sg_id],
        )
        logger.info("인스턴스 %s 격리 완료: SG %s -> [%s]", instance_id, current_sgs, target_sg_id)
        return True

    except ClientError as e:
        logger.error("인스턴스 %s 격리 중 AWS ClientError 발생: %s", instance_id, e)
        return False


def apply_remediation(
    report: IncidentReport,
    ec2_client: Any = None,
    waf_client: Any = None,
    iam_client: Any = None,
    quarantine_sg_id: str | None = None,
) -> RemediationResult:
    """침해사고 보고서를 기반으로 AWS 다중 계층 차단 조치를 실행하고 결과 반환.

    Why:
        보고서의 action_required 필드에 정의된 대응 수준에 맞춰
        EC2 Quarantine Security Group 교체(L4), WAF IPSet 갱신(L7), IAM 세션 해제를
        단계별 격리 트랜잭션으로 실행하여 복합 보안 통제를 완결함.

    Constraints:
        - report: 유효성이 검증된 IncidentReport 객체.
        - 반환값: 계층별 조치 성공 여부 딕셔너리
          (예: {"waf_blocked": False, "quarantine_applied": True, "iam_revoked": False}).

    Side-effects / Edge-cases:
        - botocore.exceptions.ClientError(권한 부족, 리소스 없음, 동시 수정 충돌) 정밀 핸들링.
        - 특정 계층 조치가 실패하더라도 나머지 계층 조치가 중단되지 않도록 단계별 독립 격리 실행.
        - action_required가 'NONE' 또는 'ALERT_ONLY'인 경우 모든 플래그를 False로 반환함.
    """
    result: RemediationResult = {
        "waf_blocked": False,
        "quarantine_applied": False,
        "iam_revoked": False,
    }

    action = report.action_required

    # 경보 전용 또는 조치 불필요 시 즉시 False 결과 반환
    if action in ("NONE", "ALERT_ONLY"):
        return result

    # 1. L4 EC2 격리 조치 (QUARANTINE_EC2 또는 BLOCK_AND_QUARANTINE)
    if action in ("QUARANTINE_EC2", "BLOCK_AND_QUARANTINE"):
        result["quarantine_applied"] = quarantine_ec2_instance(
            instance_id=report.target_identifier,
            ec2_client=ec2_client,
            quarantine_sg_id=quarantine_sg_id,
        )

    # 2. L7 WAF IP 차단 조치 (후속 티켓 구현 영역)
    if action in ("BLOCK_WAF", "BLOCK_AND_QUARANTINE", "BLOCK_IP_ONLY"):
        # TODO(cloud-a): WAFv2 IPSet /32 원자적 차단 티켓에서 연동 구현
        result["waf_blocked"] = False

    # 3. Identity IAM 임시 세션 무효화 조치 (후속 연계 영역)
    if action == "REVOKE_IAM_SESSION":
        # TODO(cloud-a): IAM 세션 무효화 인라인 정책 적용 연동 구현
        result["iam_revoked"] = False

    return result
