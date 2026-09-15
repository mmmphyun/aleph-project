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

import ipaddress
import logging
import os
from typing import Any, TypedDict

import boto3
from botocore.exceptions import ClientError

from contracts.incident import IncidentReport

logger = logging.getLogger(__name__)

DEFAULT_QUARANTINE_SG_NAME = "CloudShield-Quarantine-SG"
DEFAULT_WAF_IPSET_NAME = "CloudShield-Block-IPSet"
DEFAULT_WAF_SCOPE = "REGIONAL"
MAX_WAF_UPDATE_RETRIES = 3


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


def validate_quarantine_security_group(ec2_client: Any, sg_id: str) -> bool:
    """격리 보안 그룹의 인바운드 및 아웃바운드 규칙이 전면 차단 상태인지 검증.

    Why:
        격리 SG에 인바운드 허용 룰(예: 22/tcp) 또는 기본 아웃바운드 허용(0.0.0.0/0)이
        잔존하거나 사후 오염된 경우, 외형상 격리 성공으로 보고되더라도 침해 호스트의
        외부 C2 통신 및 내부 횡적이동(Lateral Movement)을 차단하지 못하는 결함을 방지함.

    Constraints:
        - sg_id: 'sg-'로 시작하는 AWS 보안 그룹 ID 문자열.
        - ec2_client: Boto3 EC2 클라이언트 인스턴스.
        - 검증 조건: IpPermissions(인바운드)와 IpPermissionsEgress(아웃바운드)가
          모두 빈 리스트([])여야 참으로 판정.

    Side-effects / Edge-cases:
        - describe_security_groups 호출 시 ClientError 발생 시 False 반환.
        - 허용 규칙이 1개라도 존재하는 경우 에러 로그 기록 후 False 반환.
    """
    try:
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
        security_groups = response.get("SecurityGroups", [])
        if not security_groups:
            logger.error("검증 대상 격리 보안 그룹을 찾을 수 없음: %s", sg_id)
            return False

        sg = security_groups[0]
        ingress_rules = sg.get("IpPermissions", [])
        egress_rules = sg.get("IpPermissionsEgress", [])

        if ingress_rules:
            logger.error(
                "격리 보안 그룹(%s)에 인바운드 허용 규칙(%d건)이 잔존하여 부적합함",
                sg_id,
                len(ingress_rules),
            )
            return False

        if egress_rules:
            logger.error(
                "격리 보안 그룹(%s)에 아웃바운드 허용 규칙(%d건)이 잔존하여 부적합함",
                sg_id,
                len(egress_rules),
            )
            return False

        return True
    except ClientError as e:
        logger.error("격리 보안 그룹(%s) 규칙 검증 중 ClientError 발생: %s", sg_id, e)
        return False


def quarantine_ec2_instance(
    instance_id: str,
    ec2_client: Any = None,
    quarantine_sg_id: str | None = None,
    quarantine_sg_name: str = DEFAULT_QUARANTINE_SG_NAME,
) -> bool:
    """침해 타깃 EC2의 보안 그룹을 격리 보안 그룹으로 원자적 교체.

    Why:
        침해 사고 발생 시 인/아웃바운드가 전면 차단된 단일 격리 SG로
        즉시 원자적 교체(modify_instance_attribute)하여 외부 유출 및 횡적이동을 원천 차단함.

    Constraints:
        - instance_id: 'i-' 접두사로 시작하는 유효한 AWS EC2 인스턴스 ID.
        - quarantine_sg_id가 주어지지 않은 경우 quarantine_sg_name으로 자동 탐색함.
        - 격리 SG는 인바운드/아웃바운드 규칙이 전무한 순수 격리 상태여야 함.

    Side-effects / Edge-cases:
        - 격리 SG에 허용 규칙(인바운드 또는 아웃바운드)이 남아있는 경우 격리를 거부하고 False 반환.
        - 이미 격리 SG 단독 적용 상태라도 해당 SG가 오염된 경우 실패(False) 처리하며,
          완전 격리 상태인 경우에만 중복 API 호출 없이 즉시 True 반환 (상태 기반 멱등성).
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

        # 3. 격리 보안 그룹 정책 사전 검증 (인/아웃바운드 전면 차단 상태 확인)
        if not validate_quarantine_security_group(ec2_client, target_sg_id):
            logger.error(
                "인스턴스 %s 격리 거부: 보안 그룹(%s)이 전면 차단 격리 요건을 충족하지 못함",
                instance_id,
                target_sg_id,
            )
            return False

        # 4. 멱등성 검사: 이미 격리 SG 단독 적용 상태인지 확인
        if current_sgs == [target_sg_id]:
            logger.info(
                "인스턴스 %s는 이미 유효한 격리 보안 그룹(%s)에 배치되어 있음 (멱등 처리)",
                instance_id,
                target_sg_id,
            )
            return True

        # 5. 원자적 보안 그룹 전면 교체 (기존 보안 그룹 목록을 격리 SG 1개로 단독 대체)
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[target_sg_id],
        )
        logger.info("인스턴스 %s 격리 완료: SG %s -> [%s]", instance_id, current_sgs, target_sg_id)
        return True

    except ClientError as e:
        logger.error("인스턴스 %s 격리 중 AWS ClientError 발생: %s", instance_id, e)
        return False


def find_waf_ip_set(
    waf_client: Any,
    ipset_name: str = DEFAULT_WAF_IPSET_NAME,
    scope: str = DEFAULT_WAF_SCOPE,
) -> dict[str, str] | None:
    """AWS WAFv2 IPSet 목록에서 지정된 이름의 IPSet 메타데이터를 조회.

    Why:
        WAFv2 리소스는 수정 및 조회 시 Name뿐 아니라 고유 Id 및 Scope가 필수이므로,
        사전 정의된 IPSet 명칭(CloudShield-Block-IPSet)을 기반으로 Id와 ARN을 동적 식별함.

    Constraints:
        - waf_client: Boto3 WAFv2 클라이언트 인스턴스.
        - ipset_name: 대상 IPSet 명칭 (기본값: CloudShield-Block-IPSet).
        - scope: 'REGIONAL' 또는 'CLOUDFRONT' (기본값: REGIONAL).
        - 반환값: 탐색 성공 시 {"id": ..., "name": ..., "arn": ..., "lock_token": ...},
          미발견 시 None.

    Side-effects / Edge-cases:
        - API 호출 실패(ClientError) 시 예외를 상위로 전파하지 않고 None을 반환하여
          차단 파이프라인의 안전성을 유지함.
    """
    try:
        response = waf_client.list_ip_sets(Scope=scope)
        summaries = response.get("IPSets", response.get("IPSetSummaries", []))
        for summary in summaries:
            if summary.get("Name") == ipset_name:
                return {
                    "id": str(summary.get("Id", "")),
                    "name": str(summary.get("Name", "")),
                    "arn": str(summary.get("ARN", "")),
                    "lock_token": str(summary.get("LockToken", "")),
                }
        logger.warning("WAF IPSet 탐색 실패: ipset_name=%s, scope=%s", ipset_name, scope)
        return None
    except ClientError as e:
        logger.error("WAF IPSet 목록 조회 중 AWS ClientError 발생: %s", e)
        return None


def block_ip_wafv2(
    source_ip: str,
    ipset_name: str = DEFAULT_WAF_IPSET_NAME,
    ipset_id: str | None = None,
    scope: str = DEFAULT_WAF_SCOPE,
    waf_client: Any = None,
    max_retries: int = MAX_WAF_UPDATE_RETRIES,
) -> bool:
    """공격자 IP 주소를 AWS WAFv2 IPSet에 /32 CIDR 규격으로 원자적 등록 및 차단.

    Why:
        L7 침해 공격(스프레잉, 웹 무차별 대입 등) 발생 시 단일 공격자 IP만을 정밀 차단하여
        정상 대역에 대한 오차단(Blast Radius)을 원천 방지하고, 동시성 충돌 시 LockToken 기반
        낙관적 락 재시도를 통해 차단 정책의 원자적 일관성을 보장함.

    Constraints:
        - source_ip: 단일 유효 IPv4 주소 문자열. (서브넷 미포함 시 자동으로 /32 부가).
        - ipset_id가 주어지지 않은 경우 ipset_name으로 자동 검색.
        - max_retries: 동시성 충돌(WAFOptimisticLockException) 시 최대 재시도 횟수.

    Side-effects / Edge-cases:
        - 유효하지 않은 IP 형식이 전달될 경우 작업을 즉시 거부하고 False 반환.
        - 이미 해당 IP(/32)가 차단 목록에 포함되어 있으면 중복 API 호출 없이 즉시 True 반환
          (상태 기반 멱등성).
        - 다른 프로세스와의 동시 수정 충돌 시 최신 LockToken을 재취득하여 최대 max_retries회 재시도.
        - 권한 부족, 리소스 부재 등 AWS ClientError 발생 시 상위 파이프라인 중단을
          방지하고 False 반환.
    """
    # 1. IPv4 유효성 검증 및 /32 CIDR 표준화
    normalized_ip = source_ip.strip()
    if "/" not in normalized_ip:
        target_cidr = f"{normalized_ip}/32"
    else:
        target_cidr = normalized_ip

    try:
        network = ipaddress.ip_network(target_cidr, strict=False)
        if network.version != 4:
            logger.error("IPv4만 지원됩니다: %s", source_ip)
            return False
        # 단일 호스트(/32) 차단 규격 강제
        if network.prefixlen != 32:
            logger.warning("폭발 반경 방지를 위해 /32 단일 호스트 차단만 허용됩니다: %s", source_ip)
            return False
    except ValueError as e:
        logger.error("유효하지 않은 IP 주소 규격: %s (%s)", source_ip, e)
        return False

    if waf_client is None:
        region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        waf_client = boto3.client("wafv2", region_name=region)

    for attempt in range(max_retries):
        try:
            # 2. IPSet ID 확정
            target_ipset_id = ipset_id
            if not target_ipset_id:
                found = find_waf_ip_set(waf_client, ipset_name=ipset_name, scope=scope)
                if not found:
                    logger.error("대상 WAF IPSet(%s)을 찾을 수 없음", ipset_name)
                    return False
                target_ipset_id = found["id"]

            # 3. 최신 IPSet 상세 정보 및 LockToken 조회
            get_res = waf_client.get_ip_set(
                Name=ipset_name,
                Scope=scope,
                Id=target_ipset_id,
            )
            ipset_data = get_res.get("IPSet", {})
            current_addresses = ipset_data.get("Addresses", [])
            lock_token = get_res.get("LockToken")
            description = ipset_data.get("Description", "")

            # 4. 멱등성 검사: 이미 차단 목록에 포함되어 있는지 확인
            if target_cidr in current_addresses:
                logger.info(
                    "IP %s는 이미 WAF IPSet(%s)에 등록되어 있음 (멱등 처리)",
                    target_cidr,
                    ipset_name,
                )
                return True

            # 5. 신규 주소 병합 (기존 순서 보존 및 중복 제거)
            new_addresses = list(dict.fromkeys([*current_addresses, target_cidr]))

            # 6. 낙관적 락 기반 원자적 갱신 호출
            waf_client.update_ip_set(
                Name=ipset_name,
                Scope=scope,
                Id=target_ipset_id,
                Description=description,
                Addresses=new_addresses,
                LockToken=lock_token,
            )
            logger.info(
                "WAF IPSet(%s) 차단 등록 완료: %s 추가 (총 %d개 IP 차단 중)",
                ipset_name,
                target_cidr,
                len(new_addresses),
            )
            return True

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "WAFOptimisticLockException" and attempt < max_retries - 1:
                logger.warning(
                    "WAF IPSet(%s) 동시 수정 충돌 감지(WAFOptimisticLockException). 재시도 (%d/%d)",
                    ipset_name,
                    attempt + 1,
                    max_retries,
                )
                continue
            logger.error("WAF IPSet(%s) 차단 중 AWS ClientError 발생: %s", ipset_name, e)
            return False
        except Exception as e:
            logger.error("WAF IPSet(%s) 차단 중 예기치 않은 오류 발생: %s", ipset_name, e)
            return False

    logger.error("WAF IPSet(%s) 갱신 최대 재시도 횟수(%d회) 초과 실패", ipset_name, max_retries)
    return False


def apply_remediation(
    report: IncidentReport,
    ec2_client: Any = None,
    waf_client: Any = None,
    iam_client: Any = None,
    quarantine_sg_id: str | None = None,
    waf_ipset_name: str = DEFAULT_WAF_IPSET_NAME,
    waf_ipset_id: str | None = None,
    waf_scope: str = DEFAULT_WAF_SCOPE,
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

    # 2. L7 WAF IP 차단 조치 (BLOCK_WAF, BLOCK_AND_QUARANTINE, BLOCK_IP_ONLY)
    if action in ("BLOCK_WAF", "BLOCK_AND_QUARANTINE", "BLOCK_IP_ONLY"):
        result["waf_blocked"] = block_ip_wafv2(
            source_ip=report.source_ip,
            ipset_name=waf_ipset_name,
            ipset_id=waf_ipset_id,
            scope=waf_scope,
            waf_client=waf_client,
        )

    # 3. Identity IAM 임시 세션 무효화 조치 (후속 연계 영역)
    if action == "REVOKE_IAM_SESSION":
        # TODO(cloud-a): IAM 세션 무효화 인라인 정책 적용 연동 구현
        result["iam_revoked"] = False

    return result
