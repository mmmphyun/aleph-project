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
    - 보안 분석기(analyze_incident_with_bedrock) 및
      클라우드 B 2차 전파(send_deep_analysis_slack_alert)를 호출하여
      심층 분석 결과를 SecOps 채널에 전파함.
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

# 보안 담당 LLM 분석 함수 지연 바인딩 (PR 머지 상태 유연 대응)
try:
    from detection.llm_deep_analyzer import analyze_incident_with_bedrock
except ImportError:

    def analyze_incident_with_bedrock(
        report: IncidentReport,
        raw_logs: list[str],
        bedrock_client: Any = None,
        model_id: str = "apac.amazon.nova-micro-v1:0",
    ) -> IncidentReport:
        """보안 모듈 미배포 시 원본 IncidentReport를 안전하게 유지하는 Fallback 헬퍼."""
        return report


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
        # build_llm_slack_payload가 이미 2차 카드 포맷으로 빌드되었으므로
        # send_slack_alert 내부의 격리 전송 로직을 안전 재사용함
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


def _get_incident_report_class():
    """contracts.incident.IncidentReport 클래스를 지연 임포트하여 반환."""
    from contracts.incident import IncidentReport

    return IncidentReport


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
            return incident_cls.model_validate(detail)
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

    # 3. 사후 LLM 심층 침해 분석 파이프라인 수행 (Bedrock 어댑터 호출)
    raw_logs = detail.get("raw_logs", []) if isinstance(detail, dict) else []
    if not isinstance(raw_logs, list):
        raw_logs = []

    model_id = os.getenv("BEDROCK_MODEL_ID", "apac.amazon.nova-micro-v1:0")
    try:
        analyzed_report = analyze_incident_with_bedrock(
            report=report,
            raw_logs=raw_logs,
            bedrock_client=bedrock_client,
            model_id=model_id,
        )
        response["llm_analyzed"] = True
    except Exception as exc:
        logger.error("Bedrock LLM 분석 파이프라인 실패 격리: %s", exc)
        analyzed_report = report
        response["llm_analyzed"] = False

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
