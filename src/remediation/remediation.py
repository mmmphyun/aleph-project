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
import socket
from collections.abc import Callable
from typing import Any, TypedDict

import boto3
from botocore.exceptions import ClientError

try:
    from pytest_socket import SocketBlockedError
except ImportError:
    SocketBlockedError = ()  # type: ignore[assignment, misc]

from contracts.incident import IncidentReport

logger = logging.getLogger(__name__)

DEFAULT_QUARANTINE_SG_NAME = "CloudShield-Quarantine-SG"
DEFAULT_BASELINE_SG_NAME = "CloudShield-Target-SG"
DEFAULT_WAF_IPSET_NAME = "CloudShield-Block-IPSet"
DEFAULT_WAF_SCOPE = "REGIONAL"
MAX_WAF_UPDATE_RETRIES = 3
DEFAULT_PROBE_TIMEOUT = 0.3


class RemediationResult(TypedDict):
    """AWS 다중 계층 원자적 차단 실행 결과 모델.

    Why:
        클라우드 A(차단 엔진)와 클라우드 B(Slack 알림 카드) 간에
        딕셔너리 키 이름 불일치(KeyError)로 인한 런타임 결합 실패를 원천 방지함.
    """

    waf_blocked: bool
    quarantine_applied: bool
    iam_revoked: bool


class RollbackResult(TypedDict):
    """AWS 다중 계층 원자적 복구(Rollback) 실행 결과 모델.

    Why:
        L4 EC2 Baseline SG 복원과 L7 WAF IPSet 해제 및 Identity IAM 복구 결과를
        구조화된 계약 모델로 반환하여 상위 오케스트레이터 및 리포터 모듈과의 결합도를 유지함.
    """

    waf_unblocked: bool
    quarantine_restored: bool
    iam_restored: bool


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


def probe_socket_dropped(
    target_host: str,
    port: int = 22,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    socket_fn: Callable[..., Any] | None = None,
) -> bool:
    """타깃 호스트 및 포트에 대한 L4 트래픽 침묵 폐기(DROP) 여부를 능동 탐침(Active Probe)하여 확증.

    Why:
        제어 평면(Boto3 API)의 SG 교체 완료 시각과 하이퍼바이저 패킷 필터링(Data Plane)
        실제 적용 시각 간의 시차(약 1.88초)로 인한 허위 격리 성공 보고를 차단함.
        AWS 보안 그룹은 인바운드 미허용 트래픽을 DROP(침묵 폐기)하므로,
        TCP 3-Way Handshake 시도 시 Timeout이 발생하는 것이 물리적 정상 격리 상태임.

    Constraints:
        - timeout: 기본 300ms (0.3초). 동일 리전 VPC RTT < 2ms 감안하여 10초 SLA 마진 보존.
        - 반환값: 패킷 침묵 폐기(Timeout) 시 True(격리 확증),
          연결 체결(Connect) 및 연결 거부(Refused)/오류(OSError) 발생 시 False(격리 실패/검증 불가).

    Side-effects / Edge-cases:
        - 서비스 중단(포트 닫힘)이나 네트워크 장애 환경에서 허위 성공 보고를 원천 차단함.
        - TCP Handshake 성공 시 즉시 소켓 자원을 안전하게 회수(close)함.
    """
    connect_fn = socket_fn or socket.create_connection

    try:
        sock = connect_fn((target_host, port), timeout=timeout)
        try:
            sock.close()
        except Exception:
            pass
        logger.warning(
            "L4 Active Probe 실패: 타깃 %s:%d 포트가 여전히 연결 가능함 (패킷 미차단)",
            target_host,
            port,
        )
        return False
    except TimeoutError:
        logger.info(
            "L4 Active Probe 확증: 타깃 %s:%d 포트 패킷 침묵 폐기(DROP/Timeout) 확인됨",
            target_host,
            port,
        )
        return True
    except ConnectionRefusedError as e:
        logger.warning(
            "L4 Active Probe 검증 불가(연결 거부/포트 비활성): 타깃 %s:%d (%s)",
            target_host,
            port,
            e,
        )
        return False
    except OSError as e:
        logger.warning(
            "L4 Active Probe 검증 불가(소켓/네트워크 오류): 타깃 %s:%d (%s)",
            target_host,
            port,
            e,
        )
        return False
    except Exception as e:
        if SocketBlockedError and isinstance(e, SocketBlockedError):
            logger.warning(
                "L4 Active Probe 검증 불가(pytest-socket 차단): 타깃 %s:%d (%s)",
                target_host,
                port,
                e,
            )
            return False
        raise


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
    active_probe: bool = True,
    probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
    socket_fn: Callable[..., Any] | None = None,
) -> bool:
    """침해 타깃 EC2의 보안 그룹을 격리 보안 그룹으로 원자적 교체 및 L4 데이터 평면 확증.

    Why:
        침해 사고 발생 시 인/아웃바운드가 전면 차단된 단일 격리 SG로
        즉시 원자적 교체(modify_instance_attribute)하고, 하이퍼바이저 패킷 차단(Active Probe)까지
        확증하여 침해 인스턴스의 외부 유출 및 횡적이동을 원천 차단함.

    Constraints:
        - instance_id: 'i-' 접두사로 시작하는 유효한 AWS EC2 인스턴스 ID.
        - quarantine_sg_id가 주어지지 않은 경우 quarantine_sg_name으로 자동 탐색함.
        - 격리 SG는 인바운드/아웃바운드 규칙이 전무한 순수 격리 상태여야 함.
        - active_probe: True일 경우 300ms 소켓 타임아웃을 통해 데이터 평면 DROP을 확증함.

    Side-effects / Edge-cases:
        - 격리 SG에 허용 규칙(인바운드 또는 아웃바운드)이 남아있는 경우 격리를 거부하고 False 반환.
        - 이미 격리 SG 단독 적용 상태라도 해당 SG가 오염된 경우 실패(False) 처리하며,
          완전 격리 상태인 경우에만 중복 API 호출 없이 즉시 True 반환 (상태 기반 멱등성).
        - 유효하지 않은 인스턴스 ID, 인스턴스 미존재, 권한 부족 등의 ClientError 발생 시
          False를 반환하고 상위 파이프라인의 중단을 방지함.
        - Active Probe 검증 시 소켓 연결이 체결(Connect 성공)되면 미차단으로 판정하고 False 반환.
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

        # 4. 멱등성 검사 및 데이터 평면 재검증
        if current_sgs == [target_sg_id]:
            logger.info(
                "인스턴스 %s는 이미 유효한 격리 보안 그룹(%s)에 배치되어 있음 (데이터 평면 재검증)",
                instance_id,
                target_sg_id,
            )
            if active_probe:
                target_ip = target_instance.get("PublicIpAddress") or target_instance.get(
                    "PrivateIpAddress"
                )
                if target_ip:
                    is_dropped = probe_socket_dropped(
                        target_host=target_ip,
                        port=22,
                        timeout=probe_timeout,
                        socket_fn=socket_fn,
                    )
                    if not is_dropped:
                        logger.error(
                            "인스턴스 %s L4 격리 재검증 실패: 포트 22 연결이 여전히 체결됨",
                            instance_id,
                        )
                        return False
                    logger.info(
                        "인스턴스 %s L4 데이터 평면 패킷 침묵 폐기(DROP) 재확증 완료",
                        instance_id,
                    )
            return True

        # 5. 원자적 보안 그룹 전면 교체 (기존 보안 그룹 목록을 격리 SG 1개로 단독 대체)
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[target_sg_id],
        )
        logger.info("인스턴스 %s 격리 완료: SG %s -> [%s]", instance_id, current_sgs, target_sg_id)

        # 6. L4 데이터 평면 확증 (Active Probe)
        if active_probe:
            target_ip = target_instance.get("PublicIpAddress") or target_instance.get(
                "PrivateIpAddress"
            )
            if target_ip:
                is_dropped = probe_socket_dropped(
                    target_host=target_ip,
                    port=22,
                    timeout=probe_timeout,
                    socket_fn=socket_fn,
                )
                if not is_dropped:
                    logger.error(
                        "인스턴스 %s L4 데이터 평면 격리 검증 실패: 포트 22 연결이 여전히 체결됨",
                        instance_id,
                    )
                    return False
                logger.info(
                    "인스턴스 %s L4 데이터 평면 패킷 침묵 폐기(DROP) 확증 완료",
                    instance_id,
                )

        return True

    except ClientError as e:
        logger.error("인스턴스 %s 격리 중 AWS ClientError 발생: %s", instance_id, e)
        return False


# 노션 DoD 및 인터페이스 호환을 위한 격리 함수 별칭
isolate_ec2_instance = quarantine_ec2_instance


def find_baseline_security_group(
    ec2_client: Any,
    vpc_id: str | None = None,
    group_name: str = DEFAULT_BASELINE_SG_NAME,
) -> str | None:
    """정상 운영 기준선 보안 그룹(CloudShield-Target-SG)의 GroupId를 조회.

    Why:
        복구(Rollback) 시 인프라 환경에 따라 정상 보안 그룹의 ID가 동적으로 변경될 수 있으므로,
        표준 네이밍 규약 또는 파라미터에 따라 해당 VPC 내의 정상 SG를 탐색하여 결합도를 낮춤.

    Constraints:
        - group_name: 조회 대상 기준선 보안 그룹명 (기본값: CloudShield-Target-SG).
        - 반환값: 탐색 성공 시 'sg-xxxx' 문자열, 미발견 시 None.

    Side-effects / Edge-cases:
        - AWS API 호출 실패(ClientError) 시 에러를 전파하지 않고 None을 반환하여
          복구 엔진의 예외 격리 원칙을 준수함.
    """
    filters: list[dict[str, Any]] = [{"Name": "group-name", "Values": [group_name]}]
    if vpc_id:
        filters.append({"Name": "vpc-id", "Values": [vpc_id]})

    try:
        response = ec2_client.describe_security_groups(Filters=filters)
        security_groups = response.get("SecurityGroups", [])
        if not security_groups:
            logger.warning(
                "기준선 보안 그룹 탐색 실패: group_name=%s, vpc_id=%s",
                group_name,
                vpc_id,
            )
            return None
        return str(security_groups[0]["GroupId"])
    except ClientError as e:
        logger.error("기준선 보안 그룹 조회 중 AWS ClientError 발생: %s", e)
        return None


def restore_ec2_baseline_sg(
    instance_id: str,
    ec2_client: Any = None,
    baseline_sg_id: str | None = None,
    baseline_sg_name: str = DEFAULT_BASELINE_SG_NAME,
) -> bool:
    """침해 타깃 EC2의 보안 그룹을 정상 기준선 보안 그룹(Baseline SG)으로 원자적 복원.

    Why:
        침해사고 종결, 오탐 판정 또는 모의 공격 관통 테스트 종료 후,
        격리 보안 그룹(Quarantine SG)으로 격리되었던 타깃 EC2를 기존 정상 운영 보안 그룹으로
        원자적 교체(modify_instance_attribute)하여 정상 서비스 가용성을 복원함.

    Constraints:
        - instance_id: 'i-' 접두사로 시작하는 유효한 AWS EC2 인스턴스 ID.
        - baseline_sg_id 미지정 시 환경변수(BASELINE_SG_ID) 또는 baseline_sg_name으로 자동 탐색.
        - 교체 직후 describe_instances 동기 재조회를 통해 Baseline SG 단독 적용을 확증함.

    Side-effects / Edge-cases:
        - 이미 Baseline SG 단독 적용 상태인 경우 중복 API 호출 없이 즉시 True 반환
          (상태 기반 멱등성).
        - 인스턴스 미존재, 권한 부족, API 실패(ClientError) 시 False 반환 및 결함 격리.
    """
    if ec2_client is None:
        region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        ec2_client = boto3.client("ec2", region_name=region)

    try:
        # 1. 대상 인스턴스 상태 및 VPC, 현재 연결된 보안 그룹 조회
        desc_res = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = desc_res.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            logger.error("복원 대상 인스턴스를 찾을 수 없음: %s", instance_id)
            return False

        target_instance = reservations[0]["Instances"][0]
        vpc_id = target_instance.get("VpcId")
        current_sgs = [sg["GroupId"] for sg in target_instance.get("SecurityGroups", [])]

        # 2. 복원 대상 기준선 보안 그룹 ID 확정
        target_baseline_sg_id = baseline_sg_id or os.getenv("BASELINE_SG_ID")
        if not target_baseline_sg_id:
            target_baseline_sg_id = find_baseline_security_group(
                ec2_client, vpc_id=vpc_id, group_name=baseline_sg_name
            )

        if not target_baseline_sg_id:
            logger.error(
                "인스턴스 %s 복원에 필요한 기준선 보안 그룹(%s)을 찾을 수 없음",
                instance_id,
                baseline_sg_name,
            )
            return False

        # 3. 멱등성 검사: 이미 Baseline SG 단독 적용 상태인지 확인
        if current_sgs == [target_baseline_sg_id]:
            logger.info(
                "인스턴스 %s는 이미 기준선 보안 그룹(%s) 단독 적용 상태임 (멱등 처리)",
                instance_id,
                target_baseline_sg_id,
            )
            return True

        # 4. 원자적 보안 그룹 교체 (기존 보안 그룹 목록을 Baseline SG 1개로 단독 대체)
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[target_baseline_sg_id],
        )

        # 5. Read-after-Write 동기 재조회 검증
        verify_res = ec2_client.describe_instances(InstanceIds=[instance_id])
        verified_sgs = [
            sg["GroupId"]
            for sg in verify_res["Reservations"][0]["Instances"][0].get("SecurityGroups", [])
        ]
        if verified_sgs != [target_baseline_sg_id]:
            logger.error(
                "인스턴스 %s Baseline SG 복구 검증 실패: 예상=[%s], 실제=%s",
                instance_id,
                target_baseline_sg_id,
                verified_sgs,
            )
            return False

        logger.info(
            "인스턴스 %s Baseline SG 복원 완료: SG %s -> [%s]",
            instance_id,
            current_sgs,
            target_baseline_sg_id,
        )
        return True

    except ClientError as e:
        logger.error("인스턴스 %s Baseline SG 복원 중 AWS ClientError 발생: %s", instance_id, e)
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
        next_marker: str | None = None
        while True:
            list_params: dict[str, Any] = {"Scope": scope}
            if next_marker:
                list_params["NextMarker"] = next_marker

            response = waf_client.list_ip_sets(**list_params)
            summaries = response.get("IPSets", response.get("IPSetSummaries", []))
            for summary in summaries:
                if summary.get("Name") == ipset_name:
                    return {
                        "id": str(summary.get("Id", "")),
                        "name": str(summary.get("Name", "")),
                        "arn": str(summary.get("ARN", "")),
                        "lock_token": str(summary.get("LockToken", "")),
                    }
            next_marker = response.get("NextMarker")
            if not next_marker:
                break

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
    alb_arn: str | None = None,
) -> bool:
    """공격자 IP 주소를 WAFv2 IPSet에 등록하고 Read-after-Write로 차단을 동기 확증.

    Why:
        L7 침해 공격(스프레잉, 웹 무차별 대입 등) 발생 시 단일 공격자 IP만을 정밀 차단하여
        정상 대역에 대한 오차단(Blast Radius)을 원천 방지하고, 타깃 ALB와 WebACL 간의
        결합 상태 및 IPSet 물리적 반영(Read-after-Write)을 동기 확증하여 허위 성공 보고를 차단함.

    Constraints:
        - source_ip: 단일 유효 IPv4 주소 문자열. (서브넷 미포함 시 자동으로 /32 부가).
        - ipset_id가 주어지지 않은 경우 ipset_name으로 자동 검색.
        - max_retries: 동시성 충돌(WAFOptimisticLockException) 시 최대 재시도 횟수.
        - alb_arn: 타깃 ALB ARN 지정 시 WAFv2 WebACL 결합 여부를 동기 검증함.

    Side-effects / Edge-cases:
        - 유효하지 않은 IP 형식이 전달될 경우 작업을 즉시 거부하고 False 반환.
        - alb_arn이 지정되었으나 WebACL이 결합되어 있지 않은 경우 False 반환.
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

    # 2. ALB 연동 상태 동기 검사 (지정된 경우)
    target_alb_arn = alb_arn or os.getenv("TARGET_ALB_ARN") or os.getenv("ALB_ARN")
    if target_alb_arn:
        try:
            web_acl_res = waf_client.get_web_acl_for_resource(ResourceArn=target_alb_arn)
            web_acl = web_acl_res.get("WebACL")
            if not web_acl or not web_acl.get("ARN"):
                logger.error(
                    "타깃 ALB(%s)에 연결된 WAFv2 WebACL이 존재하지 않음 (미결합 상태)",
                    target_alb_arn,
                )
                return False

            # WebACL 내 대상 IPSet 참조 차단 규칙(Block Action) 존재 검증
            rules = web_acl.get("Rules", [])
            has_blocking_rule = False
            for rule in rules:
                action = rule.get("Action", {})
                if "Block" not in action and "block" not in action:
                    continue
                statement = rule.get("Statement", {})
                ip_set_stmt = statement.get("IPSetReferenceStatement") or statement.get(
                    "ip_set_reference_statement"
                )
                if not ip_set_stmt:
                    continue
                stmt_arn = ip_set_stmt.get("ARN") or ip_set_stmt.get("arn", "")
                if ipset_name in stmt_arn or (ipset_id and ipset_id in stmt_arn):
                    has_blocking_rule = True
                    break

            if not has_blocking_rule:
                logger.error(
                    "타깃 ALB WebACL(%s)에 대상 IPSet(%s) 차단(Block) 규칙이 없음",
                    target_alb_arn,
                    ipset_name,
                )
                return False

            logger.info(
                "타깃 ALB(%s) WAFv2 WebACL 결합 및 IPSet 차단 규칙 검증 완료: %s",
                target_alb_arn,
                web_acl.get("ARN"),
            )
        except ClientError as e:
            logger.error(
                "타깃 ALB(%s) WebACL 결합 조회 중 ClientError 발생: %s",
                target_alb_arn,
                e,
            )
            return False
        except Exception as e:
            logger.error(
                "타깃 ALB(%s) WebACL 결합 조회 중 예기치 않은 오류 발생: %s",
                target_alb_arn,
                e,
            )
            return False

    for attempt in range(max_retries):
        try:
            # 3. IPSet ID 확정
            target_ipset_id = ipset_id
            if not target_ipset_id:
                found = find_waf_ip_set(waf_client, ipset_name=ipset_name, scope=scope)
                if not found:
                    logger.error("대상 WAF IPSet(%s)을 찾을 수 없음", ipset_name)
                    return False
                target_ipset_id = found["id"]

            # 4. 최신 IPSet 상세 정보 및 LockToken 조회
            get_res = waf_client.get_ip_set(
                Name=ipset_name,
                Scope=scope,
                Id=target_ipset_id,
            )
            ipset_data = get_res.get("IPSet", {})
            current_addresses = ipset_data.get("Addresses", [])
            lock_token = get_res.get("LockToken")
            description = ipset_data.get("Description")

            # 5. 멱등성 검사: 이미 차단 목록에 포함되어 있는지 확인
            if target_cidr in current_addresses:
                logger.info(
                    "IP %s는 이미 WAF IPSet(%s)에 등록되어 있음 (멱등 처리)",
                    target_cidr,
                    ipset_name,
                )
                return True

            # 6. 신규 주소 병합 (기존 순서 보존 및 중복 제거)
            new_addresses = list(dict.fromkeys([*current_addresses, target_cidr]))

            # 7. 낙관적 락 기반 원자적 갱신 호출
            # Description은 존재할 때만 전달하여 빈 문자열 규격 에러 방어
            update_kwargs: dict[str, Any] = {
                "Name": ipset_name,
                "Scope": scope,
                "Id": target_ipset_id,
                "Addresses": new_addresses,
                "LockToken": lock_token,
            }
            if description:
                update_kwargs["Description"] = description

            waf_client.update_ip_set(**update_kwargs)

            # 8. Read-after-Write 물리적 차단 목록 반영 즉시 재검증
            verify_res = waf_client.get_ip_set(
                Name=ipset_name,
                Scope=scope,
                Id=target_ipset_id,
            )
            verified_addresses = verify_res.get("IPSet", {}).get("Addresses", [])
            if target_cidr not in verified_addresses:
                logger.error(
                    "WAF IPSet(%s) Read-after-Write 검증 실패: %s가 차단 목록에 미반영됨",
                    ipset_name,
                    target_cidr,
                )
                return False

            logger.info(
                "WAF IPSet(%s) 차단 및 Read-after-Write 확증: %s (총 %d개 IP 차단 중)",
                ipset_name,
                target_cidr,
                len(verified_addresses),
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


DEFAULT_WAF_VERIFY_TIMEOUT = 30.0
DEFAULT_WAF_POLL_INTERVAL = 1.0
DEFAULT_HTTP_PROBE_TIMEOUT = 2.0


def _find_covering_cidrs(
    target_net: ipaddress.IPv4Network,
    addresses: list[str],
) -> list[str]:
    """IPSet 주소 목록에서 target_net(/32)을 포함하는 모든 IPv4 CIDR(동일 /32 및 상위 대역)을 반환.

    Why:
        단일 IP(/32)만 문자열 비교로 제거하거나 멱등 성공 처리할 경우,
        동일 IP를 포함하는 상위 대역(예: /24)이 IPSet에 남아 실제 차단이 지속됨에도
        성공으로 오판하는 보안/운영 결함을 차단함.
    """
    covering: list[str] = []
    for addr in addresses:
        try:
            net = ipaddress.ip_network(addr.strip(), strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network) and target_net.subnet_of(net):
            covering.append(addr)
    return covering


def normalize_single_ipv4(ip_str: str) -> str:
    """단일 IPv4 주소 또는 /32 CIDR 문자열에서 순수 IPv4 호스트 문자열 반환.

    Why:
        복구 스크립트 및 WAF API에서 출발지 IP와 차단 대상 IP의 정합성을 비교할 때
        /32 CIDR 표기 유무와 관계없이 동일한 IPv4 호스트 주소로 정규화하여 검증함.
    """
    cleaned = ip_str.strip()
    if "/" in cleaned:
        net = ipaddress.ip_network(cleaned, strict=True)
        if not isinstance(net, ipaddress.IPv4Network) or net.prefixlen != 32:
            raise ValueError(f"단일 IPv4(/32) 규격이 아닙니다: {ip_str}")
        return str(net.network_address)
    addr = ipaddress.ip_address(cleaned)
    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValueError(f"IPv4 규격이 아닙니다: {ip_str}")
    return str(addr)


def _default_http_probe(url: str, timeout: float) -> int:
    """대상 HTTP/HTTPS 엔드포인트로 GET 요청을 전송하고 HTTP 상태 코드를 반환."""
    import urllib.error
    import urllib.parse
    import urllib.request

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"지원하지 않는 URL 스킴입니다 (http/https만 허용): {url}")

    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return int(resp.status)
    except urllib.error.HTTPError as e:
        return int(e.code)


def verify_waf_traffic_restored(
    verify_url: str,
    timeout: float = DEFAULT_WAF_VERIFY_TIMEOUT,
    poll_interval: float = DEFAULT_WAF_POLL_INTERVAL,
    request_timeout: float = DEFAULT_HTTP_PROBE_TIMEOUT,
    http_probe_fn: Callable[[str, float], int] | None = None,
    sleep_fn: Callable[[float], None] | None = None,
    clock_fn: Callable[[], float] | None = None,
) -> bool:
    """WAF IPSet 설정 갱신 후 실제 데이터 평면(ALB/WAF 엣지)에서 HTTP 요청 성공 여부를 폴링 확증.

    Why:
        AWS WAFv2 UpdateIPSet 및 GetIPSet 재조회는 제어 평면(Control Plane) 설정 반영만 확인하며,
        실제 Regional ALB의 WAF 적용 지점까지 전파되는 데 수초-수분의 전파 지연이 발생할 수 있음.
        전파 지연 동안 HTTP 403이 지속되는 상태에서 조기 복구 완료로 판정하는 문제를 방지함.

    Constraints:
        - verify_url: 검증 대상 HTTP/HTTPS URL.
        - timeout: 최대 폴링 대기 시간(초). 0 이하일 경우 1회만 즉시 검증.
        - 반환값: 제한 시간 내 2xx/3xx 응답 확인 시 True, 403 지속 또는 타임아웃 시 False.
    """
    import time

    probe = http_probe_fn or _default_http_probe
    sleeper = sleep_fn or time.sleep
    clock = clock_fn or time.monotonic

    # 1. timeout <= 0: 명시된 1회 즉시 검사 정책
    if timeout <= 0.0:
        try:
            status_code = probe(verify_url, request_timeout)
            return 200 <= status_code < 400
        except Exception:
            return False

    # 2. timeout > 0: 마감 시각(Deadline) 기반 엄격한 잔여 시간 폴링
    start = clock()
    deadline = start + timeout
    last_status: int | str = "none"

    while True:
        now = clock()
        if now >= deadline:
            logger.error(
                "WAF 데이터 평면 트래픽 복구 확인 시간 초과(%.2fs): url=%s (마지막 상태=%s)",
                timeout,
                verify_url,
                last_status,
            )
            return False

        remaining = deadline - now
        current_req_timeout = min(request_timeout, remaining)

        try:
            status_code = probe(verify_url, current_req_timeout)
            last_status = status_code
        except Exception as e:
            if SocketBlockedError and isinstance(e, SocketBlockedError):
                logger.warning(
                    "WAF 트래픽 복구 검증 불가(pytest-socket 차단): url=%s (%s)",
                    verify_url,
                    e,
                )
                return False
            last_status = f"error:{e}"
            status_code = -1

        now_after = clock()
        if now_after > deadline:
            logger.error(
                "WAF 트래픽 프로브 응답이 제한 시간(%.2fs) 초과하여 도착함: 경과=%.2fs, status=%s",
                timeout,
                now_after - start,
                last_status,
            )
            return False

        if 200 <= status_code < 400:
            logger.info(
                "WAF 데이터 평면 트래픽 복구 확증 완료: url=%s, status=%d (경과=%.2fs)",
                verify_url,
                status_code,
                now_after - start,
            )
            return True

        if now_after >= deadline:
            return False

        remaining_sleep = deadline - now_after
        sleep_dur = min(max(0.0, poll_interval), remaining_sleep)
        if sleep_dur <= 0.0:
            return False

        sleeper(sleep_dur)
        if clock() >= deadline:
            return False


def unblock_ip_wafv2(
    source_ip: str | None = None,
    unblock_all: bool = False,
    ipset_name: str = DEFAULT_WAF_IPSET_NAME,
    ipset_id: str | None = None,
    scope: str = DEFAULT_WAF_SCOPE,
    waf_client: Any = None,
    max_retries: int = MAX_WAF_UPDATE_RETRIES,
    verify_url: str | None = None,
    verify_timeout: float = DEFAULT_WAF_VERIFY_TIMEOUT,
    poll_interval: float = DEFAULT_WAF_POLL_INTERVAL,
    probe_source_ip: str | None = None,
    observed_source_ip: str | None = None,
    observed_source_ip_fn: Callable[[], str | None] | None = None,
    http_probe_fn: Callable[[str, float], int] | None = None,
    sleep_fn: Callable[[float], None] | None = None,
    clock_fn: Callable[[], float] | None = None,
) -> bool:
    """공격자 IP를 WAFv2 IPSet에서 제거하고 제어 평면 및 선택적 트래픽 복구를 검증.

    Why:
        침해사고 실측 또는 오탐 발생 시 특정 단일 IP(/32)의 WAF 차단을 해제하되,
        비정규 CIDR(/24 등) 입력으로 인한 대역 전체 오삭제(Blast Radius)와
        상위 CIDR 잔류로 인한 허위 해제 성공 판정을 원천 차단함.

    Constraints:
        - source_ip: 단일 유효 IPv4 문자열 또는 엄격한 /32 CIDR
          (예: '198.51.100.77' 또는 '198.51.100.77/32').
          /32 이외의 프리픽스 또는 호스트 비트가 켜진 CIDR 입력은 API 호출 전에 즉시 거부됨.
        - unblock_all: True일 경우 IPSet 내 모든 차단 IP를 초기화 ([]).
        - verify_url: 지정 시 제어 평면 갱신 후 HTTP 2xx/3xx 응답 복구를 폴링 검증.
        - observed_source_ip / observed_source_ip_fn: 단일 IP 해제 시 실제 프로브 요청의
          관측된 출발지 IP (source_ip와 일치 필수).

    Side-effects / Edge-cases:
        - 대상 IP를 포함하는 상위 CIDR(예: /24)이 존재할 경우 멱등 성공 대신 False 반환.
        - 대상 /32와 상위 CIDR이 함께 등록된 경우에도 최종 검증에서 잔류를 감지하여 False 반환.
        - verify_url 지정 시 제한 시간(verify_timeout) 내 403이 해소되지 않으면 False 반환.
        - verify_url 지정 단일 IP 해제 시 실제 관측 출발지 IP 미제공 또는 불일치 시 False 반환.
        - WAFOptimisticLockException 발생 시 최신 LockToken으로 재시도.
    """
    if verify_url and not unblock_all and source_ip:
        actual_observed_ip = observed_source_ip or (
            observed_source_ip_fn() if observed_source_ip_fn else None
        )
        if not actual_observed_ip:
            logger.error(
                "WAF 트래픽 복구 검증을 위해 실제 프로브 출발지 IP 관측 근거가 필수이나 "
                "미제공됨: target=%s",
                source_ip,
            )
            return False
        try:
            target_norm = normalize_single_ipv4(source_ip)
            observed_norm = normalize_single_ipv4(actual_observed_ip)
            if target_norm != observed_norm:
                logger.error(
                    "실제 프로브 출발지 IP(%s)가 해제 대상 IP(%s)와 불일치함",
                    observed_norm,
                    target_norm,
                )
                return False
            if probe_source_ip and normalize_single_ipv4(probe_source_ip) != target_norm:
                logger.error(
                    "사용자 지정 출발지 IP(%s)가 해제 대상 IP(%s)와 불일치함",
                    probe_source_ip,
                    target_norm,
                )
                return False
        except ValueError as e:
            logger.error("출발지 IP 규격 오류로 인한 트래픽 복구 검증 거부: %s", e)
            return False
    if waf_client is None:
        region = os.getenv("AWS_DEFAULT_REGION", "ap-southeast-2")
        waf_client = boto3.client("wafv2", region_name=region)

    target_cidr: str | None = None
    target_net: ipaddress.IPv4Network | None = None
    if not unblock_all:
        if not source_ip or not isinstance(source_ip, str) or not source_ip.strip():
            logger.error("차단 해제할 source_ip가 지정되지 않았으며 unblock_all도 False임")
            return False
        try:
            target_ip_str = source_ip.strip()
            if "/" in target_ip_str:
                network = ipaddress.ip_network(target_ip_str, strict=True)
                if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 32:
                    logger.error(
                        "단일 IPv4(/32) 규격이 아닌 CIDR은 해제 대상에서 거부됨: %s",
                        source_ip,
                    )
                    return False
                target_net = network
                target_cidr = f"{network.network_address}/32"
            else:
                ip_obj = ipaddress.ip_address(target_ip_str)
                if not isinstance(ip_obj, ipaddress.IPv4Address):
                    logger.error("IPv4 규격이 아닌 주소는 해제 대상에서 거부됨: %s", source_ip)
                    return False
                target_net = ipaddress.IPv4Network(f"{ip_obj}/32")
                target_cidr = f"{ip_obj}/32"
        except ValueError as e:
            logger.error(
                "유효하지 않은 IP/CIDR 형식으로 인한 WAF 차단 해제 거부: %s (원인: %s)",
                source_ip,
                e,
            )
            return False

    for attempt in range(max_retries):
        try:
            target_ipset_id = ipset_id
            if not target_ipset_id:
                found = find_waf_ip_set(waf_client, ipset_name=ipset_name, scope=scope)
                if not found:
                    logger.error("대상 WAF IPSet(%s)을 찾을 수 없음", ipset_name)
                    return False
                target_ipset_id = found["id"]

            get_res = waf_client.get_ip_set(
                Name=ipset_name,
                Scope=scope,
                Id=target_ipset_id,
            )
            ipset_data = get_res.get("IPSet", {})
            current_addresses = ipset_data.get("Addresses", [])
            lock_token = get_res.get("LockToken")
            description = ipset_data.get("Description")

            if unblock_all:
                if not current_addresses:
                    logger.info("WAF IPSet(%s)이 이미 비어 있음 (멱등 처리)", ipset_name)
                    if verify_url:
                        return verify_waf_traffic_restored(
                            verify_url=verify_url,
                            timeout=verify_timeout,
                            poll_interval=poll_interval,
                            http_probe_fn=http_probe_fn,
                            sleep_fn=sleep_fn,
                            clock_fn=clock_fn,
                        )
                    return True
                new_addresses: list[str] = []
            else:
                assert target_cidr is not None
                assert target_net is not None
                covering_before = _find_covering_cidrs(target_net, current_addresses)
                supernets_before = [addr for addr in covering_before if addr != target_cidr]

                if target_cidr not in current_addresses:
                    if supernets_before:
                        logger.error(
                            "WAF IPSet(%s) 내 상위 CIDR(%s)이 대상 IP(%s)를 차단 중이므로 "
                            "단일 IP 해제 불가",
                            ipset_name,
                            supernets_before,
                            target_cidr,
                        )
                        return False
                    logger.info(
                        "IP %s는 WAF IPSet(%s) 차단 목록에 존재하지 않음 (멱등 처리)",
                        target_cidr,
                        ipset_name,
                    )
                    if verify_url:
                        return verify_waf_traffic_restored(
                            verify_url=verify_url,
                            timeout=verify_timeout,
                            poll_interval=poll_interval,
                            http_probe_fn=http_probe_fn,
                            sleep_fn=sleep_fn,
                            clock_fn=clock_fn,
                        )
                    return True
                new_addresses = [addr for addr in current_addresses if addr != target_cidr]

            update_kwargs: dict[str, Any] = {
                "Name": ipset_name,
                "Scope": scope,
                "Id": target_ipset_id,
                "Addresses": new_addresses,
                "LockToken": lock_token,
            }
            if description:
                update_kwargs["Description"] = description

            waf_client.update_ip_set(**update_kwargs)

            verify_res = waf_client.get_ip_set(
                Name=ipset_name,
                Scope=scope,
                Id=target_ipset_id,
            )
            verified_addresses = verify_res.get("IPSet", {}).get("Addresses", [])
            if unblock_all and verified_addresses:
                logger.error("WAF IPSet(%s) 전체 해제 실패: 잔여 주소 존재", ipset_name)
                return False
            if target_net is not None:
                remaining_covering = _find_covering_cidrs(target_net, verified_addresses)
                if remaining_covering:
                    logger.error(
                        "WAF IPSet(%s) Read-after-Write 해제 검증 실패: "
                        "%s를 차단하는 항목(%s)이 잔류함",
                        ipset_name,
                        target_cidr,
                        remaining_covering,
                    )
                    return False

            if verify_url:
                if not verify_waf_traffic_restored(
                    verify_url=verify_url,
                    timeout=verify_timeout,
                    poll_interval=poll_interval,
                    http_probe_fn=http_probe_fn,
                    sleep_fn=sleep_fn,
                    clock_fn=clock_fn,
                ):
                    return False

            verify_note = (
                "트래픽 복구 확인 완료"
                if verify_url
                else "IPSet 설정 갱신 확인, 트래픽 복구 미검증"
            )
            logger.info(
                "WAF IPSet(%s) 설정 갱신 확증 완료(%s): target=%s (잔여 %d개)",
                ipset_name,
                verify_note,
                "전체" if unblock_all else target_cidr,
                len(verified_addresses),
            )
            return True

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "WAFOptimisticLockException" and attempt < max_retries - 1:
                logger.warning(
                    "WAF IPSet(%s) 동시 수정 충돌(WAFOptimisticLockException). 재시도 (%d/%d)",
                    ipset_name,
                    attempt + 1,
                    max_retries,
                )
                continue
            logger.error("WAF IPSet(%s) 차단 해제 중 ClientError 발생: %s", ipset_name, e)
            return False
        except Exception as e:
            logger.error("WAF IPSet(%s) 차단 해제 중 예기치 않은 오류 발생: %s", ipset_name, e)
            return False

    logger.error("WAF IPSet(%s) 해제 최대 재시도 횟수(%d회) 초과 실패", ipset_name, max_retries)
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
    alb_arn: str | None = None,
    active_probe: bool = True,
    probe_timeout: float = DEFAULT_PROBE_TIMEOUT,
    socket_fn: Callable[..., Any] | None = None,
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
            active_probe=active_probe,
            probe_timeout=probe_timeout,
            socket_fn=socket_fn,
        )

    # 2. L7 WAF IP 차단 조치 (BLOCK_WAF, BLOCK_AND_QUARANTINE, BLOCK_IP_ONLY)
    if action in ("BLOCK_WAF", "BLOCK_AND_QUARANTINE", "BLOCK_IP_ONLY"):
        result["waf_blocked"] = block_ip_wafv2(
            source_ip=report.source_ip,
            ipset_name=waf_ipset_name,
            ipset_id=waf_ipset_id,
            scope=waf_scope,
            waf_client=waf_client,
            alb_arn=alb_arn,
        )

    # 3. Identity IAM 임시 세션 무효화 조치 (후속 연계 영역)
    if action == "REVOKE_IAM_SESSION":
        # TODO(cloud-a): IAM 세션 무효화 인라인 정책 적용 연동 구현
        result["iam_revoked"] = False

    return result


def apply_rollback(
    report: IncidentReport,
    ec2_client: Any = None,
    waf_client: Any = None,
    iam_client: Any = None,
    baseline_sg_id: str | None = None,
    baseline_sg_name: str = DEFAULT_BASELINE_SG_NAME,
    waf_ipset_name: str = DEFAULT_WAF_IPSET_NAME,
    waf_ipset_id: str | None = None,
    waf_scope: str = DEFAULT_WAF_SCOPE,
    verify_url: str | None = None,
    verify_timeout: float = DEFAULT_WAF_VERIFY_TIMEOUT,
    poll_interval: float = DEFAULT_WAF_POLL_INTERVAL,
    probe_source_ip: str | None = None,
    observed_source_ip: str | None = None,
    observed_source_ip_fn: Callable[[], str | None] | None = None,
    http_probe_fn: Callable[[str, float], int] | None = None,
    sleep_fn: Callable[[float], None] | None = None,
    clock_fn: Callable[[], float] | None = None,
) -> RollbackResult:
    """침해사고 보고서에 집행되었던 AWS 다중 계층 차단 조치를 원자적으로 롤백 복구.

    Why:
        apply_remediation()에 의해 L4 격리 및 L7 WAF 차단이 적용되었던 인프라를
        사고 조사 완료 또는 오탐 판정 시 안전하게 원복함.
        한 계층의 복구 실패가 다른 계층의 원복을 방해하지 않도록 계층별 독립 격리 실행함.

    Constraints:
        - report: IncidentReport 객체.
        - action_required에 따라 원래 적용되었던 계층만 대칭적으로 롤백함.
        - verify_url 지정 단일 IP 해제 시 observed_source_ip 또는 observed_source_ip_fn 필수 전달.
        - 반환값: RollbackResult (waf_unblocked, quarantine_restored, iam_restored).

    Side-effects / Edge-cases:
        - L4 복구 시 ClientError가 발생해도 L7 차단 해제는 정상 시도됨 (결함 격리).
        - 멱등성을 보장하여 이미 해제된 상태에서 중복 호출되어도 True 반환.
    """
    result: RollbackResult = {
        "waf_unblocked": False,
        "quarantine_restored": False,
        "iam_restored": False,
    }

    action = report.action_required
    if action in ("NONE", "ALERT_ONLY"):
        return result

    # 1. L4 EC2 Baseline SG 복원 (QUARANTINE_EC2 또는 BLOCK_AND_QUARANTINE 롤백)
    if action in ("QUARANTINE_EC2", "BLOCK_AND_QUARANTINE"):
        try:
            result["quarantine_restored"] = restore_ec2_baseline_sg(
                instance_id=report.target_identifier,
                ec2_client=ec2_client,
                baseline_sg_id=baseline_sg_id,
                baseline_sg_name=baseline_sg_name,
            )
        except Exception as exc:
            logger.error("L4 EC2 Baseline SG 복구 중 예외 발생 격리: %s", exc)
            result["quarantine_restored"] = False

    # 2. L7 WAF IP 차단 해제 (BLOCK_WAF, BLOCK_AND_QUARANTINE, BLOCK_IP_ONLY 롤백)
    if action in ("BLOCK_WAF", "BLOCK_AND_QUARANTINE", "BLOCK_IP_ONLY"):
        try:
            result["waf_unblocked"] = unblock_ip_wafv2(
                source_ip=report.source_ip,
                unblock_all=False,
                ipset_name=waf_ipset_name,
                ipset_id=waf_ipset_id,
                scope=waf_scope,
                waf_client=waf_client,
                verify_url=verify_url,
                verify_timeout=verify_timeout,
                poll_interval=poll_interval,
                probe_source_ip=probe_source_ip,
                observed_source_ip=observed_source_ip,
                observed_source_ip_fn=observed_source_ip_fn,
                http_probe_fn=http_probe_fn,
                sleep_fn=sleep_fn,
                clock_fn=clock_fn,
            )
        except Exception as exc:
            logger.error("L7 WAF IP 차단 해제 중 예외 발생 격리: %s", exc)
            result["waf_unblocked"] = False

    # 3. Identity IAM 복구 연계 영역
    if action == "REVOKE_IAM_SESSION":
        result["iam_restored"] = False

    return result
