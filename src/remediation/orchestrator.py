# CloudShield 오케스트레이터: Lambda 런타임 위협 분석 및 대응 파이프라인
# 소유자: 클라우드 A 담당
"""CloudWatch Logs 분할 수신 페이로드 분석 및 DynamoDB 윈도우 기반 자동 대응 오케스트레이터.

Why:
    단일 SSH 접속은 176ms 만에 종료되므로 실시간 패킷 인터셉트 차단이 불가능함.
    따라서 CloudWatch Logs Subscription Filter를 통해 비동기 인입되는 분할 배치를
    DynamoDB 원자적 카운터(AuthFailureWindow)로 누적 집계하고,
    5분 슬라이딩 윈도우 내 임계치(5회) 도달 즉시 L4 격리 및 L7 WAF 차단을 원자적으로 실행함.

Constraints:
    - 입력 event는 {"awslogs": {"data": "<base64_gzip>"}} 포맷을 준수해야 함.
    - target_identifier는 AWS EC2 인스턴스 ID 포맷(^i-[0-9a-f]{8,17}$)을 준수해야 함.
    - 차단 성공 시 DynamoDB 상태 테이블에 격리 완료 플래그를 원자적으로 마킹하여 멱등성을 보장함.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from contracts.events import CloudWatchLogsPayload, SyslogAuthEvent
from contracts.incident import IncidentReport
from remediation.auth_window import AuthFailureWindow
from remediation.remediation import RemediationResult, apply_remediation

logger = logging.getLogger(__name__)

DEFAULT_FALLBACK_INSTANCE_ID = "i-0abcd1234ef567890"


def is_remediation_successful(action_required: str, result: RemediationResult) -> bool:
    """조치 요구사항(action_required)에 부합하는 필수 차단 조치가 성공했는지 판정.

    Why:
        AWS API 호출 실패, 권한 부족, Throttling 등의 사유로 차단이 미완료되었음에도
        격리 완료(quarantined=True)를 마킹하면 5분 윈도우 동안 후속 이벤트 재시도가 억제됨.
        필수 보안 통제 계층이 확실히 적용된 경우에만 완료 마킹하여 방어 사각지대를 방지함.

    Constraints:
        - BLOCK_AND_QUARANTINE: L4 격리(quarantine_applied) 및
          L7 차단(waf_blocked) 모두 성공해야 함.
        - QUARANTINE_EC2: L4 격리(quarantine_applied) 성공해야 함.
        - BLOCK_WAF / BLOCK_IP_ONLY: L7 차단(waf_blocked) 성공해야 함.
        - REVOKE_IAM_SESSION: IAM 세션 무효화(iam_revoked) 성공해야 함.
    """
    if action_required == "BLOCK_AND_QUARANTINE":
        return bool(result.get("quarantine_applied") and result.get("waf_blocked"))
    if action_required == "QUARANTINE_EC2":
        return bool(result.get("quarantine_applied"))
    if action_required in ("BLOCK_WAF", "BLOCK_IP_ONLY"):
        return bool(result.get("waf_blocked"))
    if action_required == "REVOKE_IAM_SESSION":
        return bool(result.get("iam_revoked"))
    return False


def threat_orchestrator_handler(
    event: dict[str, Any],
    context: Any = None,
    auth_window: AuthFailureWindow | None = None,
    ec2_client: Any = None,
    waf_client: Any = None,
) -> dict[str, Any]:
    """CloudWatch Logs 이벤트를 수신하여 위협 집계 및 다중 계층 차단을 수행하는 Lambda 진입점.

    Why:
        복수의 Lambda 배치 호출로 나뉘어 들어온 동일 공격자의 분할 실패 이벤트를
        DynamoDB 원자적 상태 저장소와 연동하여 100% 탐지하고, 즉시 L4 격리 엔진을 호출함.

    Returns:
        처리 결과 딕셔너리:
        {
            "processed_events": int,
            "threats_detected": list[str],
            "incidents": list[dict[str, Any]],
            "remediation_results": list[dict[str, Any]],
        }

    Side-effects / Edge-cases:
        - 비정상/손상된 페이로드 인입 시 ValueError 처리 후 빈 결과 반환.
        - SSH 실패 로그가 아닌 정상 로그는 파싱 단계에서 안전하게 필터링됨.
    """
    response: dict[str, Any] = {
        "processed_events": 0,
        "threats_detected": [],
        "incidents": [],
        "remediation_results": [],
    }

    awslogs_data = event.get("awslogs", {}).get("data")
    if not awslogs_data:
        logger.warning("유효한 awslogs 데이터가 없는 이벤트 수신")
        return response

    # 1. CloudWatch Logs 페이로드 역직렬화 및 디코딩
    try:
        payload = CloudWatchLogsPayload.from_awslogs_data(awslogs_data)
    except Exception as exc:
        logger.error("CloudWatch Logs 페이로드 디코딩 실패: %s", exc)
        return response

    # 타깃 EC2 인스턴스 ID 식별
    target_instance_id = (
        payload.logStream
        if payload.logStream.startswith("i-")
        else os.getenv("TARGET_INSTANCE_ID", DEFAULT_FALLBACK_INSTANCE_ID)
    )

    if auth_window is None:
        auth_window = AuthFailureWindow()

    inspected_targets: set[tuple[str, str]] = set()

    # 2. 개별 로그 이벤트 파싱 및 DynamoDB 원자적 카운터 누적
    for log_event in payload.logEvents:
        parsed_event = SyslogAuthEvent.parse_line(log_event.message)
        if not parsed_event:
            continue

        response["processed_events"] += 1
        timestamp_epoch = log_event.timestamp / 1000.0

        # DynamoDB 원자적 카운터 갱신 (5분 슬라이딩 윈도우 자동 만료/리셋)
        auth_window.record_failure(
            source_ip=parsed_event.source_ip,
            username=parsed_event.username,
            timestamp_epoch=timestamp_epoch,
            count=1,
        )
        inspected_targets.add((parsed_event.source_ip, parsed_event.username))

    # 3. 누적 윈도우 기반 위협 판정 및 복합 차단 트리거
    for source_ip, username in inspected_targets:
        is_threat, rule_name, target_key = auth_window.check_threat(source_ip, username)
        if not is_threat or not rule_name:
            continue

        response["threats_detected"].append(rule_name)

        # 4. 표준 IncidentReport 계약 객체 생성
        incident_id = f"INC-{int(time.time())}-{source_ip.replace('.', '')[-4:]}"
        if rule_name == "SSH_BRUTE_FORCE":
            attack_type = "SSH Brute Force"
            mitre_id = "T1110.001"
            action_required = "BLOCK_AND_QUARANTINE"
            summary_ko = (
                f"동일 IP({source_ip}) 및 계정({username})에 대한 "
                f"5분 내 5회 이상 분할 누적 무차별 대입 공격이 탐지되었습니다."
            )
        else:
            attack_type = "SSH Password Spraying"
            mitre_id = "T1110.003"
            action_required = "BLOCK_WAF"
            summary_ko = (
                f"동일 IP({source_ip})에서 5분 내 2개 이상의 고유 계정을 시도하는 "
                f"분할 누적 패스워드 스프레잉 공격이 탐지되었습니다."
            )

        report = IncidentReport(
            incident_id=incident_id,
            attack_type=attack_type,
            mitre_id=mitre_id,
            risk_level="HIGH",
            source_ip=source_ip,
            target_identifier=target_instance_id,
            target_accounts=(username,),
            summary_ko=summary_ko,
            action_required=action_required,
            recommendations=(
                "L4 보안 그룹 전면 격리 상태 유지",
                "WAF IPSet /32 단일 호스트 차단 등록 확인",
            ),
        )
        response["incidents"].append(report.model_dump())

        # 5. L4 격리 및 L7 WAF 차단 실행
        remediation_result = apply_remediation(
            report=report,
            ec2_client=ec2_client,
            waf_client=waf_client,
        )
        response["remediation_results"].append(remediation_result)

        # 6. 필수 격리 조치 완료 검증 후 마킹 (중복 차단 억제 멱등성 및 실패 시 재시도 보장)
        if is_remediation_successful(action_required, remediation_result):
            auth_window.mark_quarantined(target_key)
            logger.info(
                "위협 대응 완료 및 격리 마킹 성공: %s -> %s (결과: %s)",
                rule_name,
                source_ip,
                remediation_result,
            )
        else:
            logger.warning(
                "위협 대응 필수 조치 미완료로 격리 마킹 생략 (차기 이벤트 재시도 허용): "
                "%s -> %s (결과: %s)",
                rule_name,
                source_ip,
                remediation_result,
            )

    return response
