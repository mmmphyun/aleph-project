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
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from contracts.incident import IncidentReport

try:
    from remediation.remediation import RemediationResult
except ImportError:
    from typing import TypedDict

    class RemediationResult(TypedDict, total=False):  # type: ignore[no-redef]
        waf_blocked: bool
        quarantine_applied: bool
        iam_revoked: bool


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


def build_slack_payload(
    report: IncidentReport,
    remediation_result: RemediationResult | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """IncidentReport 및 RemediationResult 데이터를 기반으로 Slack Block Kit 카드 페이로드 생성.

    Why:
        보안 관제 센터(SecOps) 담당자가 사고 발생 즉시 핵심 4대 지표(사고 ID, 공격 유형,
        출발지 IP, 차단 조치) 및 인프라 원자적 차단 집행 결과(L4 SG / L7 WAF / Identity IAM)를
        시각적으로 직관 파악할 수 있도록 표준화된 레이아웃을 생성함.

    Constraints:
        - report: Pydantic으로 검증된 IncidentReport 인스턴스.
        - remediation_result: 차단 엔진이 반환한 다중 계층 차단 결과 딕셔너리 (옵션).
        - 4대 필수 키 누락 방지: incident_id, rule_name, source_ip, remediation_action
        - 라벨/마크다운 포함 모든 최종 표시 문자열은 500자(헤더 150자) 안전 잘라내기 적용.

    Side-effects / Edge-cases:
        - target_accounts 또는 recommendations가 빈 튜플인 경우 대체 기본 안내 문구 렌더링.
        - risk_level(HIGH, MEDIUM, LOW)에 따른 시각적 경보 이모지 차등 매핑.
        - remediation_result가 None인 경우 기존 4대 지표 기본 블록만 렌더링하여
          하위 호환성 100% 보장.
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
    ]

    # 다중 계층 원자적 차단 집행 결과(RemediationResult) 연계 섹션 렌더링
    if remediation_result is not None:
        quarantine_applied = bool(remediation_result.get("quarantine_applied", False))
        waf_blocked = bool(remediation_result.get("waf_blocked", False))
        iam_revoked = bool(remediation_result.get("iam_revoked", False))

        # 1. L4 EC2 격리: BLOCK_AND_QUARANTINE 또는 QUARANTINE_EC2 시 필수 조치
        req_l4 = report.action_required in ("BLOCK_AND_QUARANTINE", "QUARANTINE_EC2")
        if quarantine_applied:
            l4_status = "✅ 격리 성공 (SG 전면 차단)"
        elif req_l4:
            l4_status = "❌ 격리 실패 / 미완료"
        else:
            l4_status = "ℹ️ 격리 미대상"

        # 2. L7 WAF IP 차단: BLOCK_AND_QUARANTINE, BLOCK_WAF, BLOCK_IP_ONLY 시 필수 조치
        req_l7 = report.action_required in (
            "BLOCK_AND_QUARANTINE",
            "BLOCK_WAF",
            "BLOCK_IP_ONLY",
        )
        if waf_blocked:
            l7_status = "✅ IPSet 차단 완료 (/32)"
        elif req_l7:
            l7_status = "❌ 차단 실패 / 미완료"
        else:
            l7_status = "ℹ️ 차단 미대상"

        # 3. Identity IAM 세션 무효화: REVOKE_IAM_SESSION 시 필수 조치
        req_iam = report.action_required == "REVOKE_IAM_SESSION"
        if iam_revoked:
            iam_status = "✅ 세션 만료 완료"
        elif req_iam:
            iam_status = "❌ 세션 무효화 실패 / 미완료"
        else:
            iam_status = "ℹ️ 미대상 (SSH 시나리오 제외)"

        remediation_status_text = truncate_text(
            f"*인프라 원자적 차단 집행 현황:*\n"
            f"• L4 EC2 네트워크 격리: {l4_status}\n"
            f"• L7 WAFv2 IP 차단: {l7_status}\n"
            f"• Identity IAM 세션 무효화: {iam_status}",
            MAX_FIELD_LENGTH,
        )
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": remediation_status_text,
                },
            }
        )

    blocks.extend(
        [
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
    )

    fallback_text = truncate_text(
        f"[{report.risk_level}] CloudShield 보안 경보 - {report.incident_id}: {report.attack_type}",
        MAX_FIELD_LENGTH,
    )

    result_payload: dict[str, Any] = {
        "text": fallback_text,
        "blocks": blocks,
        # 4대 필수 키 누락 방지 구조화 데이터
        "incident_id": report.incident_id,
        "rule_name": report.attack_type,
        "source_ip": report.source_ip,
        "remediation_action": report.action_required,
    }

    if remediation_result is not None:
        result_payload["remediation_result"] = {
            "waf_blocked": bool(remediation_result.get("waf_blocked", False)),
            "quarantine_applied": bool(remediation_result.get("quarantine_applied", False)),
            "iam_revoked": bool(remediation_result.get("iam_revoked", False)),
        }

    return result_payload


def send_slack_alert(
    report: IncidentReport,
    webhook_url: str,
    timeout: float = 3.0,
    remediation_result: RemediationResult | dict[str, Any] | None = None,
    max_retries: int = 1,
    retry_delay: float = 0.5,
) -> bool:
    """침해사고 분석 보고서를 Slack Block Kit 페이로드로 변환하여 Webhook 발송.

    Why:
        사고 식별자, 위험도, 출발지 IP, 대상 계정, 조치 내역, AI 요약 및 인프라 원자적
        차단 집행 결과(L4/L7/IAM)를 가독성 높은 카드 형태로 렌더링하여 실시간 상황 전파.
        Slack API 장애(네트워크 단절, 5xx, 타임아웃) 발생 시에도 Lambda 오케스트레이터의
        차단 트랜잭션과 메인 파이프라인이 중단되지 않도록 완전한 예외 격리(Fault Isolation) 보장.

    Constraints:
        - report: 유효성이 검증된 IncidentReport 객체.
        - webhook_url: Slack Incoming Webhook HTTPS 엔드포인트 URL 문자열.
        - timeout: 네트워크 요청 제한 시간 (초, 기본값 3.0). CloudShield 10초 관통 SLA 보장.
        - remediation_result: 다중 계층 차단 실행 결과 모델 (선택적).
        - max_retries: 일시 장애(5xx, 일시 연결 끊김) 시 재시도 상한 (기본값 1회).
        - retry_delay: 재시도 대기 간격 (초, 기본값 0.5초).
        - 반환값: 발송 성공 여부 (HTTP 200 수신 시 True, 실패 시 False).

    Side-effects / Edge-cases:
        - 잘못된 URL 형식(IPv6 대괄호 비정상 포함 등 ValueError) 및 비HTTPS 스킴 예외 격리.
        - Webhook 엔드포인트 네트워크 지연 또는 타임아웃(기본 3초) 방어.
        - HTTP 4xx(400 Bad Request, 403, 404, 429)는 클라이언트 오류로 판단하여
          재시도 없이 즉시 False 반환.
        - HTTP 5xx(서버 오류) 및 일시 네트워크 단절 시 최대 max_retries회 재시도 후 예외 격리 반환.
    """
    try:
        parsed = urllib.parse.urlparse(webhook_url)
        if not (parsed.scheme == "https" and parsed.netloc):
            logger.warning("유효하지 않은 Slack Webhook HTTPS URL입니다: %s", webhook_url)
            return False
    except Exception as exc:
        logger.warning(
            "유효하지 않은 Slack Webhook URL 또는 요청 형식입니다: %s (%s)", webhook_url, exc
        )
        return False

    try:
        payload = build_slack_payload(report, remediation_result=remediation_result)
        encoded_data = json.dumps(payload).encode("utf-8")
    except Exception as exc:
        logger.error("Slack Block Kit 페이로드 직렬화 실패: %s", exc)
        return False

    start_time = time.monotonic()

    for attempt in range(max_retries + 1):
        elapsed = time.monotonic() - start_time
        remaining_budget = timeout - elapsed
        if remaining_budget <= 0:
            logger.error(
                "Slack Webhook 전체 시간 예산(%.2f초) 소진으로 전송 중단 (시도: %d)",
                timeout,
                attempt + 1,
            )
            return False

        # 첫 시도 시 오버헤드에 의한 미세 오차 방지 (3.0초 정확도 호환)
        req_timeout = timeout if (attempt == 0 and elapsed < 0.05) else remaining_budget

        try:
            req = urllib.request.Request(
                url=webhook_url,
                data=encoded_data,
                headers={"Content-Type": "application/json; charset=utf-8"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=req_timeout) as response:
                status_code = getattr(response, "status", None) or response.getcode()
                if status_code == 200:
                    logger.info(
                        "Slack 알림 전송 성공: %s (시도: %d)", report.incident_id, attempt + 1
                    )
                    return True
                logger.warning(
                    "Slack Webhook 비정상 응답 코드: %s (시도: %d)", status_code, attempt + 1
                )
                # 4xx 클라이언트 에러는 재시도 없이 즉시 실패
                if status_code < 500:
                    return False
        except urllib.error.HTTPError as exc:
            logger.error(
                "Slack Webhook HTTP 오류 (%s): %s (시도: %d)", exc.code, exc.reason, attempt + 1
            )
            # 4xx 오류(클라이언트 잘못)는 재시도해도 실패하므로 즉시 종료
            if exc.code < 500:
                return False
        except TimeoutError:
            logger.error(
                "Slack Webhook 요청 시간 초과 (timeout=%.2f초, 시도: %d)",
                req_timeout,
                attempt + 1,
            )
            # 타임아웃 발생 시 재시도하지 않고 즉시 종료하여 3초 SLA 예산 준수
            return False
        except urllib.error.URLError as exc:
            # URLError 내부 원인이 타임아웃(TimeoutError 또는 문자열)인지 판별
            is_timeout_reason = isinstance(exc.reason, TimeoutError) or (
                isinstance(exc.reason, str) and "timed out" in exc.reason.lower()
            )
            if is_timeout_reason:
                logger.error(
                    "Slack Webhook 연결 시간 초과: %s (시도: %d)",
                    exc.reason,
                    attempt + 1,
                )
                return False
            logger.error("Slack Webhook 네트워크 연결 실패: %s (시도: %d)", exc.reason, attempt + 1)
        except Exception as exc:
            logger.error(
                "Slack Webhook 전송 중 예기치 않은 오류 발생: %s (시도: %d)", exc, attempt + 1
            )
            return False

        # 남은 재시도 횟수가 있으면 시간 예산 내에서 대기 후 재시도
        if attempt < max_retries:
            remaining_before_sleep = timeout - (time.monotonic() - start_time)
            if remaining_before_sleep <= 0:
                logger.warning("Slack Webhook 시간 예산 소진으로 재시도 대기 생략 및 중단")
                return False
            sleep_duration = min(retry_delay, remaining_before_sleep)
            logger.info("Slack Webhook 일시 오류로 재시도 대기 (delay=%.2f초)...", sleep_duration)
            time.sleep(sleep_duration)

    logger.error("Slack Webhook 최대 재시도 횟수(%d회) 초과로 최종 전송 실패 격리", max_retries + 1)
    return False
