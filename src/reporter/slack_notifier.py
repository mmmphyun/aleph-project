# CloudShield 전파 모듈: Slack Block Kit 알림
# 소유자: 클라우드 B 담당
"""Slack Incoming Webhook 기반 침해사고 실시간 전파 모듈.

Why:
    보안 분석 결과(IncidentReport) 및 인프라 차단 조치 결과를 SecOps 관리자 채널에
    Slack Block Kit 대화형 카드로 즉각 시각화하여 상황 인지 및 신속한 의사결정을 지원함.

Constraints:
    - Block Kit 텍스트 블록당 3,000자, 섹션 필드당 2,000자 이내 제한.
    - 요약 및 상세 필드는 500자 이내 안전 자르기(Truncate) 적용.
    - Webhook URL은 유효한 HTTPS URL 형식이어야 함.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from contracts.incident import IncidentReport

logger = logging.getLogger(__name__)

# Slack Block Kit 안전 글자 수 상한
MAX_FIELD_LENGTH = 500
MAX_HEADER_LENGTH = 150


def truncate_text(text: str, max_length: int = MAX_FIELD_LENGTH) -> str:
    """텍스트가 제한 길이를 초과할 경우 말줄임표(...)를 붙여 안전하게 자름.

    Why:
        Slack Block Kit API는 필드 및 블록 텍스트 길이 초과 시 HTTP 400(invalid_payload)
        에러를 반환하며 전체 알림 전송을 거부하므로 방어적 자르기(Truncation)가 필수적임.

    Constraints:
        - text: 원본 문자열.
        - max_length: 최대 허용 글자 수 (기본값: 500자).
        - 반환 문자열의 길이는 항상 max_length 이하를 보장함.

    Side-effects / Edge-cases:
        - text 길이가 max_length 이하인 경우 원본을 그대로 반환.
        - max_length가 3 이하인 극단적인 경우 단순 슬라이싱 반환.
    """
    if len(text) <= max_length:
        return text
    if max_length <= 3:
        return text[:max_length]
    return f"{text[: max_length - 3]}..."


def build_slack_payload(report: IncidentReport) -> dict[str, Any]:
    """IncidentReport 데이터를 기반으로 Slack Block Kit 카드 페이로드 딕셔너리 생성.

    Why:
        보안 관제 센터(SecOps) 담당자가 사고 발생 즉시 핵심 4대 지표(사고 ID, 공격 유형,
        출발지 IP, 차단 조치)를 시각적으로 직관 파악할 수 있도록 표준화된 레이아웃을 생성함.

    Constraints:
        - report: Pydantic으로 검증된 IncidentReport 인스턴스.
        - 4대 필수 키 누락 방지: incident_id, rule_name, source_ip, remediation_action
        - 라벨/마크다운 포함 모든 최종 표시 문자열은 500자(헤더 150자) 안전 잘라내기 적용.

    Side-effects / Edge-cases:
        - target_accounts 또는 recommendations가 빈 튜플인 경우 대체 기본 안내 문구 렌더링.
        - risk_level(HIGH, MEDIUM, LOW)에 따른 시각적 경보 이모지 차등 매핑.
    """
    risk_emojis = {
        "HIGH": "🚨",
        "MEDIUM": "⚠️",
        "LOW": "ℹ️",
    }
    emoji = risk_emojis.get(report.risk_level, "🔔")

    # 공격 대상 계정 포맷팅
    if report.target_accounts:
        accounts_text = ", ".join(report.target_accounts)
    else:
        accounts_text = "없음 (단일 호스트 스캔)"

    # 사후 권고 조치 목록 포맷팅
    if report.recommendations:
        rec_lines = [f"{idx + 1}. {rec}" for idx, rec in enumerate(report.recommendations)]
        recommendations_text = "\n".join(rec_lines)
    else:
        recommendations_text = "별도 권고 조치 없음 (대응 완료)"

    # 라벨 및 마크다운을 포함한 최종 표시 문자열 상한 적용 (Slack 규격 및 프로젝트 500자 기준 준수)
    header_text = truncate_text(
        f"{emoji} [CloudShield] 침해사고 긴급 탐지 및 자동 대응 알림", MAX_HEADER_LENGTH
    )
    summary_text = truncate_text(f"*사고 요약:*\n{report.summary_ko}", MAX_FIELD_LENGTH)
    accounts_block_text = truncate_text(f"*공격 대상 계정:*\n{accounts_text}", MAX_FIELD_LENGTH)
    recommendations_block_text = truncate_text(
        f"*SecOps 권고 조치:*\n{recommendations_text}", MAX_FIELD_LENGTH
    )
    context_text = truncate_text(
        f"MITRE ATT&CK: `{report.mitre_id}` | CloudShield 10-Second Auto-Remediation Pipeline",
        MAX_FIELD_LENGTH,
    )

    # fields 섹션 내 6개 필드 최종 표시 문자열 500자 상한 적용
    field_incident_id = truncate_text(
        f"*사건 ID (incident_id):*\n`{report.incident_id}`", MAX_FIELD_LENGTH
    )
    field_attack_type = truncate_text(
        f"*공격 유형 (rule_name):*\n{report.attack_type}", MAX_FIELD_LENGTH
    )
    field_source_ip = truncate_text(
        f"*출발지 IP (source_ip):*\n`{report.source_ip}`", MAX_FIELD_LENGTH
    )
    field_risk_level = truncate_text(
        f"*위험도 (risk_level):*\n*{report.risk_level}*", MAX_FIELD_LENGTH
    )
    field_target_id = truncate_text(
        f"*타깃 식별자:*\n`{report.target_identifier}`", MAX_FIELD_LENGTH
    )
    field_remediation = truncate_text(
        f"*대응 조치 (remediation_action):*\n*{report.action_required}*", MAX_FIELD_LENGTH
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": header_text,
                "emoji": True,
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": summary_text,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": field_incident_id,
                },
                {
                    "type": "mrkdwn",
                    "text": field_attack_type,
                },
                {
                    "type": "mrkdwn",
                    "text": field_source_ip,
                },
                {
                    "type": "mrkdwn",
                    "text": field_risk_level,
                },
                {
                    "type": "mrkdwn",
                    "text": field_target_id,
                },
                {
                    "type": "mrkdwn",
                    "text": field_remediation,
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": accounts_block_text,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": recommendations_block_text,
            },
        },
        {"type": "divider"},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": context_text,
                }
            ],
        },
    ]

    fallback_text = truncate_text(
        f"[{report.risk_level}] CloudShield 보안 경보 - {report.incident_id}: {report.attack_type}",
        MAX_FIELD_LENGTH,
    )

    return {
        "text": fallback_text,
        "blocks": blocks,
        # 4대 필수 키 누락 방지 구조화 데이터
        "incident_id": report.incident_id,
        "rule_name": report.attack_type,
        "source_ip": report.source_ip,
        "remediation_action": report.action_required,
    }


def send_slack_alert(
    report: IncidentReport,
    webhook_url: str,
    timeout: float = 5.0,
) -> bool:
    """침해사고 분석 보고서를 Slack Block Kit 페이로드로 변환하여 Webhook 발송.

    Why:
        사고 식별자, 위험도, 출발지 IP, 대상 계정, 조치 내역, AI 요약 및 권고안을
        가독성 높은 카드 형태로 렌더링하여 실시간 상황 공유.

    Constraints:
        - report: 유효성이 검증된 IncidentReport 객체.
        - webhook_url: Slack Incoming Webhook HTTPS 엔드포인트 URL 문자열.
        - timeout: 네트워크 요청 제한 시간 (초, 기본값 5.0).
        - 반환값: 발송 성공 여부 (HTTP 200 수신 시 True, 실패 시 False).

    Side-effects / Edge-cases:
        - 잘못된 URL 형식(IPv6 대괄호 비정상 포함 등 ValueError) 및 비HTTPS 스킴 예외 격리.
        - Webhook 엔드포인트 네트워크 지연 또는 타임아웃(기본 5초) 방어.
        - Slack API 호출 제한(Rate Limit 429) 및 잘못된 Webhook URL(HTTP 404/403) 예외 격리.
        - report.recommendations 또는 target_accounts가 빈 튜플인 경우에도 레이아웃 무결성 유지.
    """
    try:
        parsed = urllib.parse.urlparse(webhook_url)
        if not (parsed.scheme == "https" and parsed.netloc):
            logger.warning("유효하지 않은 Slack Webhook HTTPS URL입니다: %s", webhook_url)
            return False

        payload = build_slack_payload(report)
        encoded_data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            url=webhook_url,
            data=encoded_data,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=timeout) as response:
            status_code = getattr(response, "status", None) or response.getcode()
            if status_code == 200:
                logger.info("Slack 알림 전송 성공: %s", report.incident_id)
                return True
            logger.warning("Slack Webhook 비정상 응답 코드: %s", status_code)
            return False
    except ValueError as exc:
        logger.warning(
            "유효하지 않은 Slack Webhook URL 또는 요청 형식입니다: %s (%s)", webhook_url, exc
        )
        return False
    except urllib.error.HTTPError as exc:
        logger.error("Slack Webhook HTTP 오류 (%s): %s", exc.code, exc.reason)
        return False
    except urllib.error.URLError as exc:
        logger.error("Slack Webhook 네트워크 연결 실패: %s", exc.reason)
        return False
    except TimeoutError:
        logger.error("Slack Webhook 요청 시간 초과 (timeout=%s초)", timeout)
        return False
    except Exception as exc:
        logger.error("Slack Webhook 전송 중 예기치 않은 오류 발생: %s", exc)
        return False
