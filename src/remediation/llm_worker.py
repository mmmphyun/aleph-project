# CloudShield 비동기 분석 워커: Lambda 런타임 사후 LLM 침해 분석 파이프라인
# 소유자: 클라우드 A 담당
"""EventBridge 비동기 수신 사후 LLM 침해 심층 분석 워커 핸들러.

Why:
    10초 SLA를 갖는 실시간 긴급 차단(L4 SG / L7 WAF) 경로에서 수십 초가 소요되는
    Amazon Bedrock LLM 추론을 직접 호출하면 차단 타임아웃 및 장애 전파가 발생함.
    따라서 1차 차단 완료 후 EventBridge로 발행된 'ThreatRemediated' 이벤트를
    비동기 수신하여 격리된 독립 런타임에서 사후 심층 분석 및 2차 상황 전파를 전담함.

Constraints:
    - 입력 event는 AWS EventBridge 표준 스키마(dict)를 준수해야 함.
    - 소스 식별자는 'cloudshield.security', 상세 유형은 'ThreatRemediated'를 기본 수신함.
    - 런타임 환경에서 상태를 보존하지 않는 무상태(Stateless) 아키텍처를 유지함.

Side-effects / Edge-cases:
    - 보안 모듈의 프롬프트 빌더 및 파서와 결합된 Boto3 Bedrock 어댑터를 호출하여
      심층 분석 결과를 2차 Slack Block Kit 카드로 전파함.
    - Bedrock 호출 오류/타임아웃 시 1차 결정론적 IncidentReport를 안전하게 유지함.
    - Slack Webhook 미설정 또는 전송 실패 시에도 상위 프로세스가 비정상 종료되지 않도록 격리함.
    - 시스템 장애 시 플랫폼 재시도 및 DLQ 연동을 위해 미처리 예외는 삼키지 않고 전파함.
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from contracts.incident import IncidentReport

logger = logging.getLogger(__name__)

DEFAULT_BEDROCK_MODEL_ID = "apac.amazon.nova-micro-v1:0"
BEDROCK_CONNECT_TIMEOUT_SECONDS = 2
BEDROCK_READ_TIMEOUT_SECONDS = 20
BEDROCK_MAX_OUTPUT_TOKENS = 2048


def _get_incident_report_class():
    """contracts.incident.IncidentReport 클래스를 지연 임포트하여 반환."""
    from contracts.incident import IncidentReport

    return IncidentReport


def _extract_converse_text(response: Any) -> str:
    """Bedrock Converse API 응답 딕셔너리에서 텍스트 콘텐츠를 안전하게 추출.

    Why:
        Bedrock converse 응답의 role, stopReason 및 message content 블록 구조를
        검증하고 단일 텍스트 문자열로 병합함.
    """
    if not isinstance(response, dict):
        raise ValueError("Bedrock 응답은 dict 형태여야 합니다.")
    output = response.get("output")
    message = output.get("message") if isinstance(output, dict) else None
    if not isinstance(message, dict) or message.get("role") != "assistant":
        raise ValueError("유효하지 않은 assistant 메시지 응답입니다.")
    content = message.get("content")
    if not isinstance(content, list) or not content:
        raise ValueError("응답 content 블록이 비어 있습니다.")
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and "text" in block:
            parts.append(block["text"])
    if not parts:
        raise ValueError("응답 블록 내에 텍스트가 없습니다.")
    return "".join(parts)


def execute_bedrock_analysis(
    report: IncidentReport,
    raw_logs: list[str],
    bedrock_client: Any = None,
    model_id: str = DEFAULT_BEDROCK_MODEL_ID,
) -> tuple[IncidentReport, bool]:
    """보안 프롬프트 빌더 및 파서를 결합하여 Bedrock converse 호출을 실행하는 어댑터.

    Why:
        외부 Bedrock 서비스 장애(Throttling, Timeout, 모델 에러)가 발생하더라도
        결정론적 1차 IncidentReport를 유지하며, 성공 시에만 보강된 보고서와 True를 반환함.

    Returns:
        tuple[IncidentReport, bool]: (최종 IncidentReport, 보강 성공 여부)
    """
    try:
        from detection.llm_deep_analyzer import (
            build_bedrock_analysis_prompt,
            parse_bedrock_response_to_incident,
        )
    except ImportError as exc:
        logger.warning("detection.llm_deep_analyzer 모듈 임포트 실패로 원본 유지: %s", exc)
        return report, False

    try:
        prompt = build_bedrock_analysis_prompt(report, raw_logs)
    except Exception as exc:
        logger.warning("Bedrock 프롬프트 생성 실패로 원본 보고서 유지: %s", exc)
        return report, False

    owns_client = bedrock_client is None
    client = bedrock_client
    if owns_client:
        try:
            import boto3
            from botocore.config import Config

            client = boto3.client(
                "bedrock-runtime",
                config=Config(
                    connect_timeout=BEDROCK_CONNECT_TIMEOUT_SECONDS,
                    read_timeout=BEDROCK_READ_TIMEOUT_SECONDS,
                    retries={"mode": "standard", "total_max_attempts": 1},
                ),
            )
        except Exception as exc:
            logger.warning("Bedrock 클라이언트 생성 실패 격리: %s", exc)
            return report, False

    try:
        response = client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig={"maxTokens": BEDROCK_MAX_OUTPUT_TOKENS, "temperature": 0},
        )
        response_text = _extract_converse_text(response)
        parsed_report = parse_bedrock_response_to_incident(response_text, report)
        # 파서가 검증 실패 시 base_report 원본을 그대로 반환하므로 필드 갱신 여부 대조
        is_enhanced = (
            parsed_report.summary_ko != report.summary_ko
            or parsed_report.recommendations != report.recommendations
        )
        return parsed_report, is_enhanced
    except Exception as exc:
        logger.warning("Bedrock API 호출 또는 파싱 중 예외 발생 격리 (원본 유지): %s", exc)
        return report, False
    finally:
        if owns_client and client is not None and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass


# 보안 담당 analyze_incident_with_bedrock 규격 호환 래퍼
def analyze_incident_with_bedrock(
    report: IncidentReport,
    raw_logs: list[str],
    bedrock_client: Any = None,
    model_id: str = DEFAULT_BEDROCK_MODEL_ID,
) -> IncidentReport:
    """사후 LLM 심층 침해 분석을 실행하고 최종 IncidentReport를 반환."""
    analyzed_report, _ = execute_bedrock_analysis(
        report=report,
        raw_logs=raw_logs,
        bedrock_client=bedrock_client,
        model_id=model_id,
    )
    return analyzed_report


# 클라우드 B 2차 심층 분석 Slack 전송 함수 바인딩 (PR #201 기반 안전 전송)
def send_deep_analysis_slack_alert(
    report: IncidentReport,
    webhook_url: str | None = None,
    timeout: float = 5.0,
) -> bool:
    """사후 LLM 심층 분석 결과를 2차 알림 카드로 SecOps 채널에 전송.

    Why:
        클라우드 B에서 제공하는 build_llm_slack_payload 카드 빌더와
        검증된 send_slack_alert의 네트워크 타임아웃/예외 격리 전송 엔진을 결합하여
        사후 심층 분석 전용 알림을 안정적으로 발송함.
    """
    target_webhook = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
    if not target_webhook:
        logger.warning("SLACK_WEBHOOK_URL이 설정되지 않아 2차 심층 분석 알림을 건너뜁니다.")
        return False

    try:
        from reporter.slack_notifier import build_llm_slack_payload

        payload = build_llm_slack_payload(report)
        import urllib.request

        encoded_data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url=target_webhook,
            data=encoded_data,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status_code = getattr(response, "status", None) or response.getcode()
            if status_code == 200:
                logger.info("2차 LLM 심층 분석 Slack 알림 전송 성공: %s", report.incident_id)
                return True
            logger.warning("2차 LLM 심층 분석 Slack 알림 응답 비정상: %s", status_code)
            return False
    except Exception as exc:
        logger.error("2차 LLM 심층 분석 Slack 알림 전송 실패 격리: %s", exc)
        return False


def _parse_incident_report(detail: Any) -> Any | None:
    """EventBridge detail 필드(dict 또는 JSON 문자열)로부터 IncidentReport 객체를 안전 파싱."""
    incident_cls = _get_incident_report_class()
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except Exception as exc:
            logger.warning("detail JSON 역직렬화 실패: %s", exc)
            return None

    if isinstance(detail, dict):
        try:
            # extra="forbid" 계약 제약 준수: IncidentReport 스키마에 정의된 필드만 선별 추출
            valid_keys = incident_cls.model_fields.keys()
            filtered_detail = {k: v for k, v in detail.items() if k in valid_keys}
            return incident_cls.model_validate(filtered_detail)
        except Exception as exc:
            logger.warning("detail 필드의 IncidentReport 유효성 검증 실패: %s", exc)
            return None

    return None


def llm_analysis_handler(
    event: dict[str, Any],
    context: Any = None,
    *,
    bedrock_client: Any = None,
    slack_webhook_url: str | None = None,
) -> dict[str, Any]:
    """EventBridge 비동기 수신 사후 LLM 침해 분석 워커 진입점.

    Args:
        event: EventBridge가 전달한 표준 이벤트 페이로드.
        context: AWS Lambda 런타임 컨텍스트 객체.
        bedrock_client: Boto3 Bedrock Runtime 모의/실제 클라이언트 (DI).
        slack_webhook_url: Slack Webhook URL 오버라이드 (DI).

    Returns:
        수신 처리 상태 및 이벤트 메타데이터를 담은 결과 딕셔너리.

    Raises:
        ValueError: 입력 event가 유효한 딕셔너리가 아닌 경우.
    """
    if not isinstance(event, dict):
        raise ValueError("이벤트 페이로드는 딕셔너리(dict) 형식이어야 합니다.")

    source = event.get("source", "")
    detail_type = event.get("detail-type", "")
    event_id = event.get("id", "")
    detail = event.get("detail", {})

    logger.info(
        "EventBridge 비동기 분석 이벤트 수신: id=%s, source=%s, detail-type=%s",
        event_id,
        source,
        detail_type,
    )

    response: dict[str, Any] = {
        "status": "accepted",
        "event_id": event_id,
        "source": source,
        "detail_type": detail_type,
        "has_detail": bool(detail),
    }

    # 1. 대상 이벤트 소스 및 상세 유형 검증
    if source != "cloudshield.security" or detail_type != "ThreatRemediated":
        logger.warning(
            "CloudShield 비동기 분석 비대상 이벤트 수신: source=%s, detail-type=%s",
            source,
            detail_type,
        )
        return response

    # 2. IncidentReport 데이터 계약 역직렬화
    report = _parse_incident_report(detail)
    if report is None:
        logger.warning("이벤트 detail에서 유효한 IncidentReport를 추출하지 못함")
        return response

    response["incident_id"] = report.incident_id

    # 3. 사후 LLM 심층 침해 분석 파이프라인 수행 (실제 어댑터 호출)
    raw_logs = detail.get("raw_logs", []) if isinstance(detail, dict) else []
    if not isinstance(raw_logs, list):
        raw_logs = []

    model_id = os.getenv("BEDROCK_MODEL_ID", DEFAULT_BEDROCK_MODEL_ID)
    analyzed_report, is_enhanced = execute_bedrock_analysis(
        report=report,
        raw_logs=raw_logs,
        bedrock_client=bedrock_client,
        model_id=model_id,
    )
    response["llm_analyzed"] = is_enhanced

    # 4. 2차 사후 심층 분석 Slack 카드 전파
    target_webhook = slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL")
    try:
        slack_sent = send_deep_analysis_slack_alert(
            report=analyzed_report,
            webhook_url=target_webhook,
        )
        response["slack_notified"] = slack_sent
    except Exception as exc:
        logger.error("2차 심층 분석 Slack 알림 전파 중 예외 발생 격리: %s", exc)
        response["slack_notified"] = False

    return response
