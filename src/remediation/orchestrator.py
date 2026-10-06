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

from collector.cw_processor import LOG_GROUP_STREAM_MAPPING
from contracts.events import (
    CloudWatchLogsPayload,
    NginxAccessLogEvent,
    SyslogAuthEvent,
)
from detection.incident_mapper import map_threat_to_incident
from detection.rules import evaluate_web_rules
from remediation.auth_window import AuthFailureWindow
from remediation.remediation import RemediationResult, apply_remediation
from remediation.web_window import WebAttackWindow, parse_nginx_timestamp
from reporter.slack_notifier import send_slack_alert

logger = logging.getLogger(__name__)

DEFAULT_FALLBACK_INSTANCE_ID = "i-0abcd1234ef567890"
_GLOBAL_WEB_WINDOW = WebAttackWindow()


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
    slack_webhook_url: str | None = None,
    web_window: WebAttackWindow | None = None,
) -> dict[str, Any]:
    """CloudWatch Logs 이벤트를 수신하여 위협 집계, 다중 계층 차단, Slack 전파를 수행하는 진입점.

    Why:
        복수의 Lambda 배치 호출로 나뉘어 들어온 동일 공격자의 분할 실패 이벤트를
        DynamoDB 원자적 상태 저장소와 연동하여 100% 탐지하고, 즉시 L4 격리 및 L7 WAF 차단을 집행함.
        차단 집행 직후 SecOps 관제 채널에 Slack Block Kit 알림을 실시간 전파하며,
        Webhook 전송 실패/지연 시에도 인프라 차단 트랜잭션이 영향받지 않도록 완전 격리함.

    Returns:
        처리 결과 딕셔너리:
        {
            "processed_events": int,
            "threats_detected": list[str],
            "incidents": list[dict[str, Any]],
            "remediation_results": list[dict[str, Any]],
            "slack_notified": bool,
        }

    Side-effects / Edge-cases:
        - 비정상/손상된 페이로드 인입 시 ValueError 처리 후 빈 결과 반환.
        - SSH 실패 로그가 아닌 정상 로그는 파싱 단계에서 안전하게 필터링됨.
        - Slack Webhook 호출 실패(HTTPError, Timeout, 미설정) 시에도 L4/L7 차단 및
          DynamoDB 격리 마킹 상태는 롤백되지 않고 유지되며 slack_notified=False를 반환함.
    """
    response: dict[str, Any] = {
        "processed_events": 0,
        "threats_detected": [],
        "incidents": [],
        "remediation_results": [],
        "slack_notified": False,
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

    # 스트림 유형 식별 (auth vs nginx)
    stream_type = LOG_GROUP_STREAM_MAPPING.get(payload.logGroup)
    if stream_type is None:
        for log_ev in payload.logEvents:
            if SyslogAuthEvent.parse_line(log_ev.message) is not None:
                stream_type = "auth"
                break
            if NginxAccessLogEvent.parse_line(log_ev.message) is not None:
                stream_type = "nginx"
                break
        if stream_type is None:
            stream_type = "auth"

    # -------------------------------------------------------------------------
    # 분기 1: Nginx L7 웹 접근 로그 처리 파이프라인
    # -------------------------------------------------------------------------
    if stream_type == "nginx":
        if web_window is None:
            web_window = WebAttackWindow()

        # 1. 개별 로그 이벤트 파싱 및 과대 URI 개별 격리
        parsed_records: list[tuple[NginxAccessLogEvent, float, str]] = []
        for log_event in payload.logEvents:
            parsed_nginx = NginxAccessLogEvent.parse_line(log_event.message)
            if not parsed_nginx:
                continue
            response["processed_events"] += 1

            # 과대 URI 레코드 개별 격리 (4,096자 초과 시 정규화 계약의 ValueError 방지)
            if len(parsed_nginx.uri) > 4096:
                logger.warning(
                    "과대 URI 레코드 격리 (길이 초과): IP=%s 길이=%d",
                    parsed_nginx.source_ip,
                    len(parsed_nginx.uri),
                )
                continue

            ts_epoch = parse_nginx_timestamp(parsed_nginx.timestamp_str)
            if ts_epoch is None:
                ts_epoch = log_event.timestamp / 1000.0

            parsed_records.append((parsed_nginx, ts_epoch, log_event.id))

        # 2. 타임스탬프 오름차순 정렬 (실시간 공격 타임라인 재생)
        parsed_records.sort(key=lambda r: r[1])

        blocked_ips: set[str] = set()
        slack_notification_results: list[bool] = []

        # 3. 시간순 윈도우 누적 및 실시간 위협 판정
        for parsed_nginx, ts_epoch, event_id in parsed_records:
            source_ip = parsed_nginx.source_ip
            if source_ip in blocked_ips:
                continue

            added = web_window.add_event(
                target_identifier=target_instance_id,
                source_ip=source_ip,
                event_id=event_id,
                timestamp_epoch=ts_epoch,
                event=parsed_nginx,
            )
            if not added:
                logger.warning(
                    "웹 이벤트 윈도우 등록 실패 또는 중복 ID 격리 (IP=%s, EventID=%s)",
                    source_ip,
                    event_id,
                )

            active_events = web_window.get_active_events(
                target_identifier=target_instance_id,
                source_ip=source_ip,
                reference_time=ts_epoch,
            )
            if not active_events:
                continue

            try:
                is_threat, rule_name = evaluate_web_rules(active_events)
            except ValueError as exc:
                logger.error(
                    "Web 룰 평가 중 예외 발생 격리 (IP=%s): %s",
                    source_ip,
                    exc,
                )
                continue

            if not is_threat or not rule_name:
                continue

            response["threats_detected"].append(rule_name)

            incident_id = f"INC-{int(time.time())}-{source_ip.replace('.', '')[-4:]}"
            report = map_threat_to_incident(
                is_threat=True,
                rule_name=rule_name,
                source_ip=source_ip,
                target_accounts=(),
                target_identifier=target_instance_id,
                incident_id=incident_id,
            )
            response["incidents"].append(report.model_dump())

            # WAF IPSet 차단 실행 (L7 원자적 차단)
            remediation_result = apply_remediation(
                report=report,
                ec2_client=ec2_client,
                waf_client=waf_client,
            )
            response["remediation_results"].append(remediation_result)

            if is_remediation_successful(report.action_required, remediation_result):
                web_window.clear_ip(target_instance_id, source_ip, reference_time=ts_epoch)
                blocked_ips.add(source_ip)
                logger.info(
                    "Web L7 위협 대응 완료: %s -> %s (결과: %s)",
                    rule_name,
                    source_ip,
                    remediation_result,
                )
            else:
                logger.warning(
                    "Web L7 위협 대응 필수 조치 미완료: %s -> %s (결과: %s)",
                    rule_name,
                    source_ip,
                    remediation_result,
                )

            # Slack 알림 전파 (완전 결함 격리)
            target_webhook = slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL")
            slack_success = False
            if target_webhook:
                try:
                    slack_success = send_slack_alert(
                        report=report,
                        webhook_url=target_webhook,
                        remediation_result=remediation_result,
                    )
                except Exception as exc:
                    logger.error("Slack 알림 전파 중 예외 발생 격리 (차단 유지): %s", exc)
                    slack_success = False
            else:
                logger.warning("SLACK_WEBHOOK_URL이 설정되지 않아 알림 발송을 생략합니다.")
            slack_notification_results.append(slack_success)

        if slack_notification_results:
            response["slack_notified"] = all(slack_notification_results)
        else:
            response["slack_notified"] = False

        return response

    # -------------------------------------------------------------------------
    # 분기 2: Syslog SSH 인증 실패 로그 처리 파이프라인
    # -------------------------------------------------------------------------
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

    slack_notification_results: list[bool] = []

    # 3. 누적 윈도우 기반 위협 판정 및 복합 차단 트리거
    for source_ip, username in inspected_targets:
        threat_check = auth_window.check_threat(source_ip, username)
        if not threat_check.is_threat or not threat_check.rule_name:
            continue

        rule_name = threat_check.rule_name
        target_key = threat_check.target_key
        detected_accounts = threat_check.detected_accounts or (username,)

        response["threats_detected"].append(rule_name)

        # 4. 보안 매퍼(map_threat_to_incident)를 통한 표준 IncidentReport 계약 객체 생성
        # Why: 공격 유형별 MITRE 메타데이터, 위험도, 조치 지시(action_required)의
        #      단일 진실 공급원(SSOT)을 보안 도메인 매퍼에 일원화하여 정책 불일치를 방지함.
        #      특히 Password Spraying의 경우 누적 윈도우에 기록된 실제 공격 대상 고유
        #      계정 집합(detected_accounts)을 보존 전달함.
        incident_id = f"INC-{int(time.time())}-{source_ip.replace('.', '')[-4:]}"
        report = map_threat_to_incident(
            is_threat=True,
            rule_name=rule_name,
            source_ip=source_ip,
            target_accounts=detected_accounts,
            target_identifier=target_instance_id,
            incident_id=incident_id,
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
        if is_remediation_successful(report.action_required, remediation_result):
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

        # 7. Slack 알림 전파 (차단 결과 결합 및 완전 결함 격리)
        target_webhook = slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        slack_success = False
        if target_webhook:
            try:
                slack_success = send_slack_alert(
                    report=report,
                    webhook_url=target_webhook,
                    remediation_result=remediation_result,
                )
            except Exception as exc:
                # Slack Webhook 네트워크 오류, 타임아웃, 런타임 예외 발생 시에도
                # 앞서 완료된 L4/L7 차단 및 마킹 상태를 절대 롤백하지 않고 완전 격리함
                logger.error("Slack 알림 전파 중 예외 발생 격리 (차단 유지): %s", exc)
                slack_success = False
        else:
            logger.warning("SLACK_WEBHOOK_URL이 설정되지 않아 알림 발송을 생략합니다.")
        slack_notification_results.append(slack_success)

    if slack_notification_results:
        response["slack_notified"] = all(slack_notification_results)
    else:
        response["slack_notified"] = False

    return response
