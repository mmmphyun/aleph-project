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

import json
import logging
import os
import time
from typing import Any

import boto3
from botocore.config import Config

from collector.cw_processor import LOG_GROUP_STREAM_MAPPING
from contracts.events import (
    CloudWatchLogsPayload,
    NginxAccessLogEvent,
    SyslogAuthEvent,
)
from contracts.incident import IncidentReport
from detection.incident_mapper import map_threat_to_incident
from detection.rules import evaluate_web_rules
from remediation.auth_window import AuthFailureWindow
from remediation.remediation import RemediationResult, apply_remediation
from remediation.web_window import PersistenceError, WebAttackWindow, parse_nginx_timestamp
from reporter.slack_notifier import send_slack_alert

logger = logging.getLogger(__name__)

DEFAULT_FALLBACK_INSTANCE_ID = "i-0abcd1234ef567890"
_GLOBAL_WEB_WINDOW = WebAttackWindow()


MAX_RAW_LOG_LINES_PER_EVENT = 50
MAX_RAW_LOG_LINE_CHARS = 4096
MAX_RAW_LOG_BYTES_PER_EVENT = 32768


def _bound_raw_logs_for_event(raw_logs: list[str] | None) -> list[str]:
    """EventBridge 전송 및 LLM 프롬프트 한도를 위해 원문 로그 목록을 안전하게 상한 바운딩.

    Why:
        EventBridge PutEvents 페이로드 한도(256KB) 및 Bedrock 프롬프트 한도(50줄, 32KiB)를
        준수하여, 비동기 이벤트 발행 실패나 역직렬화 오버헤드를 원천 차단함.
    """
    if not raw_logs or not isinstance(raw_logs, list):
        return []

    bounded: list[str] = []
    remaining_bytes = MAX_RAW_LOG_BYTES_PER_EVENT
    for line in raw_logs[:MAX_RAW_LOG_LINES_PER_EVENT]:
        if not isinstance(line, str):
            continue
        if remaining_bytes <= 0:
            break
        prefix = line[:MAX_RAW_LOG_LINE_CHARS]
        encoded = prefix.encode("utf-8")
        trimmed = encoded[:remaining_bytes].decode("utf-8", errors="ignore")
        if trimmed:
            bounded.append(trimmed)
            remaining_bytes -= len(trimmed.encode("utf-8"))
    return bounded


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


def emit_threat_resolved_event(
    report: IncidentReport,
    events_client: Any = None,
    raw_logs: list[str] | None = None,
    stage_timestamps: dict[str, Any] | None = None,
) -> bool:
    """위협 차단 완료 후 EventBridge로 비동기 사후 분석 이벤트를 발행.

    Why:
        10초 SLA를 갖는 실시간 긴급 차단(L4 SG / L7 WAF)과 수십 초가 소요되는
        사후 LLM 심층 분석을 아키텍처 레벨에서 비동기 분리(Asynchronous Decoupling)하기 위함.
        차단 완료 후 'ThreatRemediated' 이벤트를 발행하여 비동기 LLM 워커를 격리 구동함.

    Constraints:
        - Source: "cloudshield.security"
        - DetailType: "ThreatRemediated"
        - Detail: report.model_dump() 기반 딕셔너리에 raw_logs 및
          pipeline_timestamps를 포함한 JSON 규격.
        - EventBridge SDK 호출 실패(ClientError, BotoCoreError, FailedEntryCount > 0 등) 시에도
          이미 집행된 L4/L7 인프라 차단 트랜잭션을 절대 롤백하지 않고 False를 안전 반환함.

    Side-effects / Edge-cases:
        - events_client 미주입 시 짧은 타임아웃(연결 2초, 읽기 3초)의 기본 클라이언트를 생성함.
        - 통신 실패 시 에러 로깅 후 False를 반환하여 메인 오케스트레이터의 정상 종료를 보장함.
    """
    if not isinstance(report, IncidentReport):
        logger.error("유효하지 않은 IncidentReport 객체 인입: %s", type(report))
        return False

    client = events_client
    if client is None:
        client = boto3.client(
            "events",
            config=Config(
                connect_timeout=2,
                read_timeout=3,
                retries={"mode": "standard", "total_max_attempts": 1},
            ),
        )

    try:
        import json

        detail_dict: dict[str, Any] = report.model_dump()
        detail_dict["raw_logs"] = _bound_raw_logs_for_event(raw_logs)
        if stage_timestamps:
            detail_dict["pipeline_timestamps"] = dict(stage_timestamps)

        entry = {
            "Source": "cloudshield.security",
            "DetailType": "ThreatRemediated",
            "Detail": json.dumps(detail_dict, ensure_ascii=False),
        }
        res = client.put_events(Entries=[entry])
        failed_count = res.get("FailedEntryCount", 0)
        if failed_count > 0:
            entries = res.get("Entries", [])
            err_msg = entries[0].get("ErrorMessage", "Unknown error") if entries else "Unknown"
            logger.error(
                "EventBridge PutEvents 발행 실패 (FailedEntryCount=%d, error=%s)",
                failed_count,
                err_msg,
            )
            return False

        logger.info(
            "EventBridge ThreatRemediated 발행 성공: incident_id=%s, source_ip=%s, count=%d",
            report.incident_id,
            report.source_ip,
            len(detail_dict["raw_logs"]),
        )
        return True
    except Exception as exc:
        logger.error("EventBridge PutEvents 호출 중 예외 발생 격리 (차단 유지): %s", exc)
        return False


def threat_orchestrator_handler(
    event: dict[str, Any],
    context: Any = None,
    auth_window: AuthFailureWindow | None = None,
    ec2_client: Any = None,
    waf_client: Any = None,
    slack_webhook_url: str | None = None,
    web_window: WebAttackWindow | None = None,
    events_client: Any = None,
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

            try:
                added = web_window.add_event(
                    target_identifier=target_instance_id,
                    source_ip=source_ip,
                    event_id=event_id,
                    timestamp_epoch=ts_epoch,
                    event=parsed_nginx,
                )
                if not added:
                    logger.info("중복 웹 이벤트 스킵 (IP=%s, EventID=%s)", source_ip, event_id)
            except PersistenceError as exc:
                logger.error(
                    "웹 이벤트 윈도우 영속화 실패 격리 (IP=%s, EventID=%s): %s",
                    source_ip,
                    event_id,
                    exc,
                )
                response.setdefault("persistence_errors", []).append(f"{source_ip}:{event_id}")
                continue

            try:
                active_events = web_window.get_active_events(
                    target_identifier=target_instance_id,
                    source_ip=source_ip,
                    reference_time=ts_epoch,
                )
            except PersistenceError as exc:
                logger.error(
                    "웹 이벤트 윈도우 이력 조회 실패 격리 (IP=%s, EventID=%s): %s",
                    source_ip,
                    event_id,
                    exc,
                )
                response.setdefault("persistence_errors", []).append(f"{source_ip}:{event_id}")
                continue

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

            detected_epoch = time.time()
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
            remediated_epoch = time.time()
            response["remediation_results"].append(remediation_result)

            # CloudWatch 대응 시간 및 집행 결과 정형 JSON 메트릭 로깅 (Grafana 4사분면 대조용)
            web_metric_log = {
                "event_type": "ThreatRemediatedMetric",
                "incident_id": incident_id,
                "rule_name": rule_name,
                "source_ip": source_ip,
                "action_required": report.action_required,
                "remediation_success": is_remediation_successful(
                    report.action_required, remediation_result
                ),
                "duration_seconds": round(remediated_epoch - detected_epoch, 4),
                "pipeline_timestamps": {
                    "detected_epoch": detected_epoch,
                    "remediated_epoch": remediated_epoch,
                    "duration_seconds": round(remediated_epoch - detected_epoch, 4),
                },
            }
            logger.info(json.dumps(web_metric_log))

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

            # 8. EventBridge 비동기 분석 이벤트 발행 (차단 성공 시에만 발행, 통신 실패 격리)
            if is_remediation_successful(report.action_required, remediation_result):
                try:
                    # 사후 LLM 심층 분석을 위해 active_events 및 현재 배치 로그 추출
                    raw_logs_candidate: list[str] = [
                        ev.raw_message for ev in active_events if hasattr(ev, "raw_message")
                    ]
                    batch_raw_logs = [
                        ev.message
                        for ev in payload.logEvents
                        if getattr(NginxAccessLogEvent.parse_line(ev.message), "source_ip", None)
                        == source_ip
                    ]
                    for b_log in batch_raw_logs:
                        if b_log not in raw_logs_candidate:
                            raw_logs_candidate.append(b_log)

                    emit_threat_resolved_event(
                        report=report,
                        events_client=events_client,
                        raw_logs=raw_logs_candidate,
                        stage_timestamps={
                            "detected_epoch": detected_epoch,
                            "remediated_epoch": remediated_epoch,
                        },
                    )
                except Exception as exc:
                    logger.error("Web L7 EventBridge 이벤트 발행 중 예외 발생 격리: %s", exc)

        if slack_notification_results:
            response["slack_notified"] = all(slack_notification_results)
        else:
            response["slack_notified"] = False

        if response.get("persistence_errors"):
            failed_keys = ", ".join(response["persistence_errors"])
            raise PersistenceError(
                f"DynamoDB 윈도우 영속화/조회 실패로 Lambda 재처리 신호 전달: [{failed_keys}]"
            )

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

        detected_epoch = time.time()
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
        remediated_epoch = time.time()
        response["remediation_results"].append(remediation_result)

        # CloudWatch 대응 시간 및 집행 결과 정형 JSON 메트릭 로깅 (Grafana 4사분면 대조용)
        ssh_metric_log = {
            "event_type": "ThreatRemediatedMetric",
            "incident_id": incident_id,
            "rule_name": rule_name,
            "source_ip": source_ip,
            "action_required": report.action_required,
            "remediation_success": is_remediation_successful(
                report.action_required, remediation_result
            ),
            "duration_seconds": round(remediated_epoch - detected_epoch, 4),
            "pipeline_timestamps": {
                "detected_epoch": detected_epoch,
                "remediated_epoch": remediated_epoch,
                "duration_seconds": round(remediated_epoch - detected_epoch, 4),
            },
        }
        logger.info(json.dumps(ssh_metric_log))

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

        # 8. EventBridge 비동기 분석 이벤트 발행 (차단 성공 시에만 발행, 통신 실패 격리)
        if is_remediation_successful(report.action_required, remediation_result):
            try:
                # 사후 LLM 심층 분석을 위해 정확한 공격자 IP 로그만 추출
                relevant_raw_logs = [
                    ev.message
                    for ev in payload.logEvents
                    if getattr(SyslogAuthEvent.parse_line(ev.message), "source_ip", None)
                    == source_ip
                ]
                emit_threat_resolved_event(
                    report=report,
                    events_client=events_client,
                    raw_logs=relevant_raw_logs,
                    stage_timestamps={
                        "detected_epoch": detected_epoch,
                        "remediated_epoch": remediated_epoch,
                    },
                )
            except Exception as exc:
                logger.error("SSH EventBridge 이벤트 발행 중 예외 발생 격리: %s", exc)

    if slack_notification_results:
        response["slack_notified"] = all(slack_notification_results)
    else:
        response["slack_notified"] = False

    return response
