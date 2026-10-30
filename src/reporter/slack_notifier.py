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
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any

from contracts.incident import IncidentReport

try:
    from remediation.remediation import DEFAULT_WAF_IPSET_NAME, RemediationResult
except ImportError:
    DEFAULT_WAF_IPSET_NAME = "CloudShield-Block-IPSet"
    from typing import TypedDict

    class RemediationResult(TypedDict, total=False):  # type: ignore[no-redef]
        waf_blocked: bool
        quarantine_applied: bool
        iam_revoked: bool


logger = logging.getLogger(__name__)

# Slack Block Kit 안전 글자 수 상한
MAX_FIELD_LENGTH = 500
MAX_HEADER_LENGTH = 150
MAX_SLACK_BLOCKS = 50


def escape_slack_text(text: str) -> str:
    """Slack mrkdwn 제어 문자(&, <, >)를 안전한 HTML 엔티티로 이스케이프.

    Why:
        Slack Block Kit의 mrkdwn 텍스트 블록은 `<`, `>`, `&`를 특수 제어 문법
        (예: <!channel> 브로드캐스트, URL 링크, 사용자 멘션)으로 해석함.
        공격 페이로드(XSS 스크립트, 경로 순회 등)나 외부 입력에 포함된 특수문자를
        사전에 이스케이프하지 않으면 원치 않는 채널 멘션 전파나 메시지 파싱 깨짐이 발생함.

    Constraints:
        - 반드시 `&`를 먼저 `&amp;`로 치환한 후, `<`를 `&lt;`, `>`를 `&gt;`로 순차 치환해야 함
          (이중 인코딩 방지).
        - Slack 규격(https://docs.slack.dev/messaging/formatting-message-text/#escaping-text)상
          오직 &, <, > 세 문자만 엔티티 변환 대상임.

    Side-effects / Edge-cases:
        - 빈 문자열 인입 시 빈 문자열 반환.
        - 순수 텍스트 변환으로 런타임 예외가 발생하지 않음.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


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


def _split_escaped_slack_text(text: str, max_length: int) -> list[str]:
    """Slack 이스케이프 결과를 엔티티 중간에서 자르지 않고 여러 조각으로 분할한다."""
    if max_length < 5:
        raise ValueError("Slack 텍스트 조각 상한은 5자 이상이어야 합니다")

    chunks: list[str] = []
    current = ""
    for character in text:
        token = escape_slack_text(character)
        if current and len(current) + len(token) > max_length:
            chunks.append(current)
            if len(chunks) >= MAX_SLACK_BLOCKS:
                raise ValueError(f"Slack 카드 블록 상한({MAX_SLACK_BLOCKS}개)을 초과했습니다")
            current = ""
        current += token
    if current or not chunks:
        chunks.append(current)
    return chunks


def build_mrkdwn_sections(
    label: str,
    value: str,
    *,
    empty_value: str,
    max_length: int = MAX_FIELD_LENGTH,
) -> list[dict[str, Any]]:
    """긴 표시 문자열을 생략하지 않고 여러 Slack section 블록으로 렌더링한다.

    Why:
        2차 LLM 보고서는 요약과 권고가 500자를 넘을 수 있으므로 말줄임 처리하면
        관제 판단 근거가 사라진다. 블록별 프로젝트 상한은 지키되 원문 전체를 보존한다.
    Constraints:
        라벨을 포함한 각 블록은 ``max_length`` 이하이며 Slack 제어 문자는 이스케이프한다.
        단일 카드의 Slack 상한(50블록)을 넘는 입력은 조용히 유실하지 않고 예외로 알린다.
    Side-effects / Edge-cases:
        외부 호출이나 상태 변경은 없다. HTML 엔티티는 조각 경계에서 분리되지 않는다.
    """
    rendered_value = value if value else empty_value
    if not 5 <= max_length <= MAX_FIELD_LENGTH:
        raise ValueError(f"Slack 섹션 상한은 5~{MAX_FIELD_LENGTH}자여야 합니다")
    escaped_label = escape_slack_text(label)
    first_prefix = f"*{escaped_label}:*\n"
    if len(first_prefix) >= max_length:
        raise ValueError("Slack 섹션 라벨이 텍스트 상한보다 깁니다")

    chunks = _split_escaped_slack_text(rendered_value, max_length - len(first_prefix))
    blocks = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{first_prefix}{chunks[0]}"},
        }
    ]
    for chunk in chunks[1:]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chunk}})
    return blocks


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
        accounts_text = ", ".join(escape_slack_text(acc) for acc in report.target_accounts)
    else:
        accounts_text = "없음 (단일 호스트 스캔)"

    # 사후 권고 조치 목록 포맷팅
    # Why: recommendations가 없을 때 고정 문구 "대응 완료"를 표시하면,
    #      BLOCK_IP_ONLY 등 WAF 차단 실패 시 현황 섹션의 ❌와 모순되는 상태를 노출함.
    #      지시된 모든 계층의 결과를 확인해야 부분 성공을 전체 완료로 오인하지 않는다.
    # Constraints / Edge-cases: 결과 키 누락은 미완료이며 결과 미전달은 성공 근거가 아니다.
    if report.recommendations:
        rec_lines = [
            f"{idx + 1}. {escape_slack_text(rec)}" for idx, rec in enumerate(report.recommendations)
        ]
        recommendations_text = "\n".join(rec_lines)
    elif remediation_result is not None:
        req_waf = report.action_required in (
            "BLOCK_AND_QUARANTINE",
            "BLOCK_WAF",
            "BLOCK_IP_ONLY",
        )
        failed_actions = []
        if req_waf and not bool(remediation_result.get("waf_blocked", False)):
            failed_actions.append("수동 WAF IPSet 차단 및 인프라 점검 권고 (차단 실패)")
        if report.action_required in ("BLOCK_AND_QUARANTINE", "QUARANTINE_EC2") and not bool(
            remediation_result.get("quarantine_applied", False)
        ):
            failed_actions.append("수동 EC2 네트워크 격리 및 보안 그룹 점검 권고 (격리 미완료)")
        if report.action_required == "REVOKE_IAM_SESSION" and not bool(
            remediation_result.get("iam_revoked", False)
        ):
            failed_actions.append("수동 IAM 세션 무효화 및 권한 점검 권고 (세션 무효화 미완료)")
        if failed_actions:
            recommendations_text = "\n".join(failed_actions)
        else:
            recommendations_text = "별도 권고 조치 없음 (대응 완료)"
    else:
        recommendations_text = "별도 권고 조치 없음 (대응 결과 미확인)"

    # 라벨 및 마크다운을 포함한 최종 표시 문자열 상한 적용 (Slack 규격 및 프로젝트 500자 기준 준수)
    header_text = truncate_text(
        f"{emoji} [CloudShield] 침해사고 긴급 탐지 및 자동 대응 알림", MAX_HEADER_LENGTH
    )
    summary_text = truncate_text(
        f"*사고 요약:*\n{escape_slack_text(report.summary_ko)}", MAX_FIELD_LENGTH
    )
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
        f"*사건 ID (incident_id):*\n`{escape_slack_text(report.incident_id)}`", MAX_FIELD_LENGTH
    )
    field_attack_type = truncate_text(
        f"*공격 유형 (rule_name):*\n{escape_slack_text(report.attack_type)}", MAX_FIELD_LENGTH
    )
    field_source_ip = truncate_text(
        f"*출발지 IP (source_ip):*\n`{escape_slack_text(report.source_ip)}`", MAX_FIELD_LENGTH
    )
    field_risk_level = truncate_text(
        f"*위험도 (risk_level):*\n*{escape_slack_text(report.risk_level)}*", MAX_FIELD_LENGTH
    )
    field_target_id = truncate_text(
        f"*타깃 식별자:*\n`{escape_slack_text(report.target_identifier)}`", MAX_FIELD_LENGTH
    )
    field_remediation = truncate_text(
        f"*대응 조치 (remediation_action):*\n*{escape_slack_text(report.action_required)}*",
        MAX_FIELD_LENGTH,
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

        # 1. L4 EC2 격리: BLOCK_AND_QUARANTINE 또는 QUARANTINE_EC2 시에만 필수 조치.
        #    Why: quarantine_applied 결과 체크를 req_l4와 AND로 결합하여
        #         미지시 액션(BLOCK_IP_ONLY 등)에서 잘못된 성공 결과가 인입되더라도
        #         "✅ 격리 성공" 오표시를 원천 차단함.
        req_l4 = report.action_required in ("BLOCK_AND_QUARANTINE", "QUARANTINE_EC2")
        if req_l4 and quarantine_applied:
            l4_status = "✅ 격리 성공 (SG 전면 차단)"
        elif req_l4:
            l4_status = "❌ 격리 실패 / 미완료"
        else:
            l4_status = "ℹ️ 격리 미대상"

        # 2. L7 WAF IP 차단: BLOCK_AND_QUARANTINE, BLOCK_WAF, BLOCK_IP_ONLY 시 필수 조치.
        #    Why: waf_blocked 결과 체크를 req_l7와 AND로 결합하여
        #         미지시 액션에서 성공 결과 오표시를 방지함.
        req_l7 = report.action_required in (
            "BLOCK_AND_QUARANTINE",
            "BLOCK_WAF",
            "BLOCK_IP_ONLY",
        )
        if req_l7 and waf_blocked:
            l7_status = "✅ IPSet 차단 완료 (/32)"
        elif req_l7:
            l7_status = "❌ 차단 실패 / 미완료"
        else:
            l7_status = "ℹ️ 차단 미대상"

        # 3. Identity IAM 세션 무효화: REVOKE_IAM_SESSION 시에만 필수 조치.
        #    Why: iam_revoked 결과 체크를 req_iam과 AND로 결합하여
        #         미지시 액션에서 성공 결과 오표시를 방지함.
        req_iam = report.action_required == "REVOKE_IAM_SESSION"
        if req_iam and iam_revoked:
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
        f"[{report.risk_level}] CloudShield 보안 경보 - "
        f"{escape_slack_text(report.incident_id)}: {escape_slack_text(report.attack_type)}",
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


def build_waf_slack_payload(
    report: IncidentReport,
    remediation_result: RemediationResult | dict[str, Any] | None = None,
    ipset_name: str | None = None,
) -> dict[str, Any]:
    """L7 WAF 웹 침해사고 전용 Slack Block Kit 알림 카드 페이로드 생성.

    Why:
        L7 Web 공격(웹 브루트포스, 디렉토리 스캐닝, 파라미터 스프레잉) 탐지 및
        AWS WAFv2 IPSet /32 차단 집행 결과를 SecOps 관리자 채널에 WAF 중심 레이아웃으로
        즉각 시각화하여 웹 보안 상태를 명확히 인지하도록 지원함.

    Constraints:
        - 4대 필수 키 누락 방지: incident_id, rule_name, source_ip, remediation_action
        - 모든 블록 텍스트는 500자(헤더 150자) 안전 잘라내기(truncate_text) 적용.
        - WAF IPSet 명세 및 차단 결과 상태를 시각적으로 강조.

    Side-effects / Edge-cases:
        - remediation_result가 전달되지 않은 경우에도 WAF 차단 대기 상태를 안전하게 표시.
        - target_accounts가 비어 있는 경우 '웹 엔드포인트 전역 스캔' 문구 제공.
        - recommendations가 비어 있는 경우 remediation_result 상태(완료/실패/대기)에 부합하도록
          권고 조치 문구를 동적으로 매핑하여 집행 현황과의 상태 모순 방지.
    """
    risk_emojis = {
        "HIGH": "🚨",
        "MEDIUM": "🛡️",
        "LOW": "ℹ️",
    }
    emoji = risk_emojis.get(report.risk_level, "🛡️")

    header_text = truncate_text(
        f"{emoji} [CloudShield] L7 WAF 웹 침해사고 탐지 및 차단 알림", MAX_HEADER_LENGTH
    )
    summary_text = truncate_text(
        f"*L7 웹 위협 요약:*\n{escape_slack_text(report.summary_ko)}", MAX_FIELD_LENGTH
    )

    field_incident_id = truncate_text(
        f"*사건 ID (incident_id):*\n`{escape_slack_text(report.incident_id)}`", MAX_FIELD_LENGTH
    )
    field_attack_type = truncate_text(
        f"*공격 유형 (rule_name):*\n{escape_slack_text(report.attack_type)}", MAX_FIELD_LENGTH
    )
    field_source_ip = truncate_text(
        f"*차단 IP (source_ip):*\n`{escape_slack_text(report.source_ip)}`", MAX_FIELD_LENGTH
    )
    field_risk_level = truncate_text(
        f"*위험도 (risk_level):*\n*{escape_slack_text(report.risk_level)}*", MAX_FIELD_LENGTH
    )
    field_target_id = truncate_text(
        f"*타깃 인스턴스:*\n`{escape_slack_text(report.target_identifier)}`", MAX_FIELD_LENGTH
    )
    field_remediation = truncate_text(
        f"*대응 조치 (remediation_action):*\n*{escape_slack_text(report.action_required)}*",
        MAX_FIELD_LENGTH,
    )

    waf_target_name = ipset_name or DEFAULT_WAF_IPSET_NAME
    # 강제 카드 선택은 표시 형식만 변경하며, 미지시된 WAF 집행을 실패로 판정하지 않는다.
    req_waf = report.action_required in ("BLOCK_WAF", "BLOCK_IP_ONLY", "BLOCK_AND_QUARANTINE")
    if not req_waf:
        waf_status = f"ℹ️ AWS WAFv2 IPSet `{waf_target_name}` 차단 미대상"
    elif remediation_result is not None:
        waf_blocked = bool(remediation_result.get("waf_blocked", False))
        if waf_blocked:
            waf_status = f"✅ AWS WAFv2 IPSet `{waf_target_name}` /32 등록 차단 집행 완료"
        else:
            waf_status = f"❌ AWS WAFv2 IPSet `{waf_target_name}` 차단 실패 / 미완료"
    else:
        waf_status = f"⏳ AWS WAFv2 IPSet `{waf_target_name}` 차단 집행 진행 중 / 대기"

    waf_detail_text = truncate_text(
        f"*L7 WAF 방어 계층 집행 현황:*\n"
        f"• 차단 계층: AWS WAFv2 WebACL & IPSet\n"
        f"• 차단 대상: `{report.source_ip}/32`\n"
        f"• 상태: {waf_status}",
        MAX_FIELD_LENGTH,
    )

    if report.target_accounts:
        accounts_text = ", ".join(escape_slack_text(acc) for acc in report.target_accounts)
    else:
        accounts_text = "지정 계정 없음 (웹 엔드포인트 URL/디렉토리 스캐닝)"
    accounts_block_text = truncate_text(
        f"*공격 대상 엔드포인트/계정:*\n{accounts_text}", MAX_FIELD_LENGTH
    )

    if report.recommendations:
        rec_lines = [
            f"{idx + 1}. {escape_slack_text(rec)}" for idx, rec in enumerate(report.recommendations)
        ]
        recommendations_text = "\n".join(rec_lines)
    elif not req_waf:
        recommendations_text = "별도 WAF 권고 조치 없음 (차단 미대상)"
    elif remediation_result is not None:
        waf_blocked = bool(remediation_result.get("waf_blocked", False))
        if waf_blocked:
            recommendations_text = "별도 권고 조치 없음 (WAF 차단 완료)"
        else:
            recommendations_text = "수동 차단 및 웹 방화벽 점검 권고 (WAF 차단 실패)"
    else:
        recommendations_text = "별도 권고 조치 없음 (차단 집행 진행 중 / 대기)"
    recommendations_block_text = truncate_text(
        f"*SecOps 웹 방어 권고 조치:*\n{recommendations_text}", MAX_FIELD_LENGTH
    )

    context_text = truncate_text(
        f"MITRE ATT&CK: `{report.mitre_id}` | AWS WAFv2 L7 Defense Layer | "
        f"CloudShield 10-Second Auto-Remediation",
        MAX_FIELD_LENGTH,
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
                {"type": "mrkdwn", "text": field_incident_id},
                {"type": "mrkdwn", "text": field_attack_type},
                {"type": "mrkdwn", "text": field_source_ip},
                {"type": "mrkdwn", "text": field_risk_level},
                {"type": "mrkdwn", "text": field_target_id},
                {"type": "mrkdwn", "text": field_remediation},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": waf_detail_text,
            },
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
        f"[{report.risk_level}] CloudShield L7 WAF 차단 - "
        f"{escape_slack_text(report.incident_id)}: {escape_slack_text(report.attack_type)}",
        MAX_FIELD_LENGTH,
    )

    result_payload: dict[str, Any] = {
        "text": fallback_text,
        "blocks": blocks,
        "incident_id": report.incident_id,
        "rule_name": report.attack_type,
        "source_ip": report.source_ip,
        "remediation_action": report.action_required,
        "is_waf_card": True,
    }

    if remediation_result is not None:
        result_payload["remediation_result"] = {
            "waf_blocked": bool(remediation_result.get("waf_blocked", False)),
            "quarantine_applied": bool(remediation_result.get("quarantine_applied", False)),
            "iam_revoked": bool(remediation_result.get("iam_revoked", False)),
        }

    return result_payload


def build_llm_slack_payload(
    report: IncidentReport,
    report_url: str | None = None,
) -> dict[str, Any]:
    """사후 LLM 심층 분석 결과를 2차 알림 카드로 생성한다.

    Why:
        초기 차단 알림과 사후 분석을 구분하고 동일 incident_id로 연계한다.
    Constraints:
        기존 IncidentReport 계약을 소비하며 최종 표시 텍스트는 500자 이내다.
        action_required는 분석 권고이며 실제 집행 성공을 의미하지 않는다.
    Side-effects / Edge-cases:
        네트워크나 상태 저장 없이 새 페이로드를 반환한다. 빈 분석/권고는
        대체 문구로 표시하며 잘못된 입력의 예외는 호출자에게 전파한다.
    """

    fields = [
        ("사건 ID", report.incident_id),
        ("공격 유형", report.attack_type),
        ("출발지 IP", report.source_ip),
        ("분석 위험도", report.risk_level),
        ("대상 인스턴스", report.target_identifier),
        ("MITRE ATT&CK", report.mitre_id),
    ]
    recommendations = "\n".join(
        f"{index + 1}. {item}" for index, item in enumerate(report.recommendations)
    )
    accounts = ", ".join(report.target_accounts)
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "CloudShield 2차 LLM 심층 분석"},
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": truncate_text(f"*{label}:*\n{escape_slack_text(value)}"),
                }
                for label, value in fields
            ],
        },
    ]
    blocks.extend(
        build_mrkdwn_sections(
            "LLM 분석 요약",
            report.summary_ko if report.summary_ko.strip() else "",
            empty_value="분석 요약 없음",
        )
    )
    blocks.extend(
        build_mrkdwn_sections("공격 대상 계정/엔드포인트", accounts, empty_value="지정 대상 없음")
    )
    blocks.extend(
        build_mrkdwn_sections("후속 권고 조치", recommendations, empty_value="추가 권고 조치 없음")
    )
    blocks.extend(
        build_mrkdwn_sections(
            "분석 권고 액션 (집행 결과 아님)", report.action_required, empty_value="NONE"
        )
    )
    if report_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📄 상사 보고용 상세 리포트 열기"},
                        "url": report_url,
                        "style": "primary",
                    }
                ],
            }
        )
    if len(blocks) > MAX_SLACK_BLOCKS:
        raise ValueError(f"Slack 카드 블록 상한({MAX_SLACK_BLOCKS}개)을 초과했습니다")

    payload: dict[str, Any] = {
        "text": truncate_text(
            f"[2차 LLM 심층 분석][{report.risk_level}] "
            f"{escape_slack_text(report.incident_id)}: {escape_slack_text(report.attack_type)}"
        ),
        "blocks": blocks,
        "incident_id": report.incident_id,
        "rule_name": report.attack_type,
        "source_ip": report.source_ip,
        "remediation_action": report.action_required,
        "is_llm_card": True,
    }
    if report_url:
        payload["report_url"] = report_url

    return payload


def build_recovery_slack_payload(
    report: IncidentReport,
    recovery_result: Mapping[str, Any],
) -> dict[str, Any]:
    """복구 엔진 결과를 동일 사건에 연결한 3차 Slack 알림 카드로 생성한다.

    Why:
        탐지·분석 알림과 실제 복구 관측을 분리해 복구 완료를 추정하거나 과장하지 않는다.
    Constraints:
        apply_rollback의 기존 결과 키를 소비하며 지시된 계층만 집계한다.
        API 설정 복구와 실제 통신 회복은 구분하며 누락/비불리언 값은 성공 근거가 아니다.
    Side-effects / Edge-cases:
        입력 키 누락은 '미확인'으로 표시하며 외부 호출이나 인프라 변경은 수행하지 않는다.
    """

    def display(key: str, fallback: str = "미확인") -> str:
        value = recovery_result.get(key)
        return str(value) if value not in (None, "") else fallback

    layers = [
        (
            "L4 EC2 Baseline SG",
            "quarantine_restored",
            report.action_required in ("BLOCK_AND_QUARANTINE", "QUARANTINE_EC2"),
        ),
        (
            "L7 WAF IP 차단 해제",
            "waf_unblocked",
            report.action_required in ("BLOCK_AND_QUARANTINE", "BLOCK_WAF", "BLOCK_IP_ONLY"),
        ),
        ("Identity IAM", "iam_restored", report.action_required == "REVOKE_IAM_SESSION"),
    ]
    required_results = [recovery_result.get(key) for _, key, required in layers if required]
    if not required_results:
        recovery_status = "복구 미대상"
    elif all(value is True for value in required_results):
        recovery_status = "설정 복구 확인"
    elif any(value is False for value in required_results):
        recovery_status = "복구 실패 / 일부 미완료"
    else:
        recovery_status = "복구 결과 미확인"
    layer_lines = []
    for label, key, required in layers:
        value = recovery_result.get(key)
        if not required:
            state = "미대상"
        elif value is True:
            state = "설정 복구 확인"
        elif value is False:
            state = "실패 / 미완료"
        else:
            state = "미확인"
        layer_lines.append(f"• {label}: {state}")

    details_value = recovery_result.get("details")
    if details_value is None:
        details_value = ()
    if isinstance(details_value, str):
        details = details_value
    elif isinstance(details_value, Sequence):
        details = "\n".join(f"{index + 1}. {item}" for index, item in enumerate(details_value))
    else:
        details = str(details_value)

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "CloudShield 3차 복구 결과 알림"},
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": truncate_text(f"*사건 ID:*\n`{escape_slack_text(report.incident_id)}`"),
                },
                {
                    "type": "mrkdwn",
                    "text": f"*복구 상태:*\n{recovery_status}",
                },
                {
                    "type": "mrkdwn",
                    "text": truncate_text(f"*출발지 IP:*\n`{escape_slack_text(report.source_ip)}`"),
                },
                {
                    "type": "mrkdwn",
                    "text": truncate_text(
                        f"*엔진 보고 시각:*\n{escape_slack_text(display('t_restored_iso'))}"
                    ),
                },
            ],
        },
    ]
    blocks.extend(
        build_mrkdwn_sections("계층별 복구 결과", "\n".join(layer_lines), empty_value="미확인")
    )
    traffic_status = "확인" if recovery_result.get("traffic_verified") is True else "미확인"
    blocks.extend(
        build_mrkdwn_sections(
            "복구 검증 결과",
            f"엔진 검증: {display('verification_status')}\n실제 통신 회복: {traffic_status}",
            empty_value="미확인",
        )
    )
    blocks.extend(build_mrkdwn_sections("복구 상세", details, empty_value="추가 상세 없음"))
    if len(blocks) > MAX_SLACK_BLOCKS:
        raise ValueError(f"Slack 카드 블록 상한({MAX_SLACK_BLOCKS}개)을 초과했습니다")

    return {
        "text": truncate_text(
            f"[3차 복구 결과][{recovery_status}] "
            f"{escape_slack_text(report.incident_id)}: {escape_slack_text(report.attack_type)}"
        ),
        "blocks": blocks,
        "incident_id": report.incident_id,
        "rule_name": report.attack_type,
        "source_ip": report.source_ip,
        "remediation_action": report.action_required,
        "recovery_status": recovery_status,
        "is_recovery_card": True,
    }


def send_slack_alert(
    report: IncidentReport,
    webhook_url: str,
    timeout: float = 3.0,
    remediation_result: RemediationResult | dict[str, Any] | None = None,
    max_retries: int = 1,
    retry_delay: float = 0.5,
    use_waf_card: bool | None = None,
    ipset_name: str | None = None,
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
        - use_waf_card: WAF 전용 카드 강제 여부
          (기본값: report.action_required == "BLOCK_WAF" 자동 감지).
        - ipset_name: WAF 카드에 표시할 IPSet 이름 (옵션).
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
        # BLOCK_IP_ONLY는 SSH 대응이므로 웹 전용 카드는 BLOCK_WAF에만 자동 선택한다.
        is_waf = use_waf_card if use_waf_card is not None else report.action_required == "BLOCK_WAF"
        if is_waf:
            payload = build_waf_slack_payload(
                report, remediation_result=remediation_result, ipset_name=ipset_name
            )
        else:
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


def _mask_webhook_url(url: str) -> str:
    """Slack Webhook URL의 인증 토큰 경로를 마스킹하여 로그 누출 방지.

    Why:
        Slack Incoming Webhook URL은 경로 부분에 민감한 인증 토큰(Secret)이 포함되어 있음.
        오류 경로 로깅 시 URL 전체를 출력하면 CloudWatch 등에 자격증명이 영구 기록되므로
        스킴과 도메인만 남기고 경로 토큰을 마스킹하여 보안 규정을 준수함.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/***[MASKED]***"
    except Exception:
        pass
    return "***[MASKED_URL]***"


# 2차 심층 분석 Webhook 동시 실행 자원 상한선 (스레드 무한 누적 방지)
MAX_CONCURRENT_SLACK_REQUESTS = 2
_SLACK_REQUEST_SEMAPHORE = threading.Semaphore(MAX_CONCURRENT_SLACK_REQUESTS)


def _execute_single_slack_post(
    target_url: str,
    encoded_data: bytes,
    timeout_limit: float,
    response_container: list[tuple[int | None, Exception | None]],
    done_event: threading.Event,
    cancel_event: threading.Event,
    semaphore: threading.Semaphore,
) -> None:
    """워커 스레드에서 HTTP POST를 실행하고 완료 시 세마포어를 해제."""
    try:
        req = urllib.request.Request(
            url=target_url,
            data=encoded_data,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_limit) as response:
            if cancel_event.is_set():
                if hasattr(response, "close"):
                    response.close()
                return
            status_code = getattr(response, "status", None) or response.getcode()
            response_container.append((status_code, None))
    except Exception as exc:
        if not cancel_event.is_set():
            response_container.append((None, exc))
    finally:
        done_event.set()
        semaphore.release()


def send_llm_slack_alert(
    report: IncidentReport,
    webhook_url: str | None = None,
    timeout: float = 3.0,
    max_retries: int = 1,
    retry_delay: float = 0.5,
    report_url: str | None = None,
) -> bool:
    """사후 LLM 심층 분석 보고서를 Slack Block Kit 카드로 렌더링하여 Webhook 발송.

    Why:
        사후 LLM 심층 분석 결과(공격 요약, 근본 원인, MITRE ATT&CK 기술, 후속 권고 사항 등)를
        SecOps 관리자 채널에 2차 대화형 카드로 즉시 전파함.
        Slack API 장애(네트워크 단절, 5xx, 타임아웃) 및 시스템 자원 고갈 시에도
        호출 런타임 및 비동기 파이프라인이 무음 비정상 종료(Silent Crash)되지 않도록
        완전한 예외 격리(Fault Isolation), 엄격한 전체 Deadline 집행,
        Bounded 자원 관리를 보장함.

    Constraints:
        - report: 유효성이 검증된 IncidentReport 객체.
        - webhook_url: Slack Incoming Webhook HTTPS 엔드포인트 URL 문자열.
          미지정 시 환경변수(SLACK_WEBHOOK_URL)에서 자동 조회.
        - timeout: 전체 호출 완료 제한 시간(초, 기본값 3.0초). 개별 소켓 타임아웃뿐만
          아니라 헤더/데이터 수신 누적 시간을 포함한 전체 deadline을 엄격히 강제함.
        - max_retries: 일시 장애(5xx, 일시 연결 끊김) 시 재시도 상한 (기본값 1회).
        - retry_delay: 재시도 대기 간격 (초, 기본값 0.5초).
        - 반환값: 발송 성공 여부 (전체 deadline 내 HTTP 200 수신 시 True, 실패 시 False).

    Side-effects / Edge-cases:
        - URL 미설정 또는 빈 문자열 인입 시 경고 로그 후 False 반환.
        - 비HTTPS 스킴, 파싱 에러, 경로 공백 등 잘못된 URL 형식 발생 시
          모든 예외 로그에서 비밀 토큰을 절대 출력하지 않고 오류 타입명만 기록 격리 후 False 반환.
        - HTTP 4xx(400 Bad Request, 403, 404, 429)는 클라이언트 오류로 판단하여
          재시도 없이 즉시 False 반환.
        - 타임아웃 및 전체 deadline 초과(누적 지연 포함) 발생 시
          cancel_event 트리거 후 즉시 False 반환.
        - 백그라운드 지연 스레드가 누적되더라도 MAX_CONCURRENT_SLACK_REQUESTS(2) 상한선으로
          동시 실행 자원을 엄격히 통제하여 스레드 무한 누적 방지.
        - 스레드 시작 실패(RuntimeError 등) 발생 시에도 호출자에게 전파하지 않고 False 안전 격리.
        - HTTP 5xx(서버 오류) 및 일시 네트워크 단절 시 남은 예산 내에서 최대 max_retries회 재시도.
        - 모든 예외는 로그 기록 후 False로 격리되어 호출자에게 결함이 전파되지 않음.
    """
    target_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
    if not target_url:
        logger.warning(
            "Slack Webhook URL이 설정되지 않아 2차 심층 분석 알림 전송 건너뜁니다 (id=%s)",
            report.incident_id,
        )
        return False

    try:
        parsed = urllib.parse.urlparse(target_url)
        if not (parsed.scheme == "https" and parsed.netloc):
            masked_url = _mask_webhook_url(target_url)
            logger.warning(
                "유효하지 않은 Slack Webhook HTTPS URL입니다 (스킴 및 도메인 확인 필요): %s",
                masked_url,
            )
            return False
    except Exception as exc:
        logger.warning(
            "유효하지 않은 Slack Webhook URL 또는 요청 형식입니다 (오류 유형: %s)",
            type(exc).__name__,
        )
        return False

    try:
        payload = build_llm_slack_payload(report, report_url=report_url)
        encoded_data = json.dumps(payload).encode("utf-8")
    except Exception as exc:
        logger.error("2차 LLM Slack Block Kit 페이로드 직렬화 실패: %s", exc)
        return False

    start_time = time.monotonic()

    for attempt in range(max_retries + 1):
        elapsed = time.monotonic() - start_time
        remaining_budget = timeout - elapsed
        if remaining_budget <= 0:
            logger.error(
                "2차 LLM Slack Webhook 전체 시간 예산(%.2f초) 소진으로 전송 중단 (시도: %d)",
                timeout,
                attempt + 1,
            )
            return False

        req_timeout = remaining_budget

        # 1. 동시 실행 자원 상한선 세마포어 획득 대기 (현재 남은 예산 한도 내)
        acquired = _SLACK_REQUEST_SEMAPHORE.acquire(
            blocking=True, timeout=max(0.001, remaining_budget)
        )
        if not acquired:
            logger.error(
                "2차 LLM Slack Webhook 동시 자원 한도(%d) 초과 및 대기 시간 만료 (시도: %d)",
                MAX_CONCURRENT_SLACK_REQUESTS,
                attempt + 1,
            )
            return False

        # 2. 세마포어 획득 직후 전체 deadline 기준 남은 예산 재계산
        elapsed_after_acquire = time.monotonic() - start_time
        remaining_budget = timeout - elapsed_after_acquire
        if remaining_budget <= 0:
            _SLACK_REQUEST_SEMAPHORE.release()
            logger.error(
                "2차 LLM Slack Webhook 세마포어 대기 중 시간 예산(%.2f초) 소진 취소 (시도: %d)",
                timeout,
                attempt + 1,
            )
            return False

        req_timeout = remaining_budget

        response_container: list[tuple[int | None, Exception | None]] = []
        req_done = threading.Event()
        cancel_event = threading.Event()

        # 2. 스레드 생성 및 시작 (시작 실패 RuntimeError 완벽 격리)
        req_start = time.monotonic()
        try:
            thread = threading.Thread(
                target=_execute_single_slack_post,
                args=(
                    target_url,
                    encoded_data,
                    req_timeout,
                    response_container,
                    req_done,
                    cancel_event,
                    _SLACK_REQUEST_SEMAPHORE,
                ),
                daemon=True,
            )
            thread.start()
        except Exception as exc:
            _SLACK_REQUEST_SEMAPHORE.release()
            logger.error(
                "2차 LLM Slack Webhook 실행 작업 시작 실패 격리 (유형: %s, 시도: %d)",
                type(exc).__name__,
                attempt + 1,
            )
            return False

        completed = req_done.wait(timeout=max(0.001, req_timeout))
        req_elapsed = time.monotonic() - req_start

        # 실제 벽시계 기준 타임아웃 또는 가상 monotonic 타임 누적 초과 판별
        if not completed or req_elapsed > req_timeout:
            cancel_event.set()
            logger.error(
                "2차 LLM Slack Webhook 요청 시간 초과 (timeout=%.2f초, 경과=%.2f초, 시도: %d)",
                req_timeout,
                req_elapsed,
                attempt + 1,
            )
            return False

        if not response_container:
            return False

        status_code, exc = response_container[0]

        # 전체 호출 경과 시간 최종 검증 (느린 헤더/누적 지연 초과 격리)
        total_elapsed = time.monotonic() - start_time
        if total_elapsed > timeout:
            cancel_event.set()
            logger.error(
                "2차 LLM Slack Webhook 전체 deadline(%.2f초) 초과 실패 (소요=%.2f초, 시도: %d)",
                timeout,
                total_elapsed,
                attempt + 1,
            )
            return False

        if exc is None and status_code == 200:
            logger.info(
                "2차 LLM 심층 분석 Slack 알림 전송 성공: %s (시도: %d)",
                report.incident_id,
                attempt + 1,
            )
            return True

        if exc is not None:
            if isinstance(exc, urllib.error.HTTPError):
                logger.error(
                    "2차 LLM Slack Webhook HTTP 오류 (코드: %s, 유형: %s, 시도: %d)",
                    exc.code,
                    type(exc).__name__,
                    attempt + 1,
                )
                if exc.code < 500:
                    return False
            elif isinstance(exc, TimeoutError):
                logger.error(
                    "2차 LLM Slack Webhook 요청 시간 초과 (timeout=%.2f초, 시도: %d)",
                    req_timeout,
                    attempt + 1,
                )
                return False
            elif isinstance(exc, urllib.error.URLError):
                is_timeout_reason = isinstance(exc.reason, TimeoutError) or (
                    isinstance(exc.reason, str) and "timed out" in exc.reason.lower()
                )
                if is_timeout_reason:
                    logger.error(
                        "2차 LLM Slack Webhook 연결 시간 초과 (유형: %s, 시도: %d)",
                        type(getattr(exc, "reason", exc)).__name__,
                        attempt + 1,
                    )
                    return False
                logger.error(
                    "2차 LLM Slack Webhook 네트워크 연결 실패 (유형: %s, 시도: %d)",
                    type(getattr(exc, "reason", exc)).__name__,
                    attempt + 1,
                )
            else:
                # InvalidURL 등 일반 예외 시 URL/토큰이 포함될 수 있는 exc 원문 노출 차단
                logger.error(
                    "2차 LLM Slack Webhook 전송 중 오류 발생 (유형: %s, 시도: %d)",
                    type(exc).__name__,
                    attempt + 1,
                )
                return False
        else:
            logger.warning(
                "2차 LLM Slack Webhook 비정상 응답 코드: %s (시도: %d)",
                status_code,
                attempt + 1,
            )
            if status_code is not None and status_code < 500:
                return False

        if attempt < max_retries:
            remaining_before_sleep = timeout - (time.monotonic() - start_time)
            if remaining_before_sleep <= 0:
                logger.warning("2차 LLM Slack Webhook 시간 예산 소진으로 재시도 대기 생략 및 중단")
                return False
            sleep_duration = min(retry_delay, remaining_before_sleep)
            logger.info(
                "2차 LLM Slack Webhook 일시 오류로 재시도 대기 (delay=%.2f초)...",
                sleep_duration,
            )
            time.sleep(sleep_duration)

    logger.error(
        "2차 LLM Slack Webhook 최대 재시도 횟수(%d회) 초과로 최종 전송 실패 격리",
        max_retries + 1,
    )
    return False


def send_recovery_slack_alert(
    report: IncidentReport,
    recovery_result: Mapping[str, Any],
    webhook_url: str | None = None,
    timeout: float = 3.0,
    max_retries: int = 1,
    retry_delay: float = 0.5,
) -> bool:
    """복구 엔진(Rollback) 결과를 3차 Slack Block Kit 카드로 렌더링하여 Webhook 발송.

    Why:
        L4 격리 해제 및 L7 WAF 차단 해제 집행 결과를 동일 incident_id 기반의
        3차 카드로 관제 채널에 즉시 전파함.
        Slack API 장애(네트워크 단절, 5xx, 타임아웃) 발생 시에도 복구 트랜잭션과
        상위 프로세스가 중단되지 않도록 완전한 예외 격리(Fault Isolation) 보장.

    Constraints:
        - report: 유효성이 검증된 IncidentReport 객체.
        - recovery_result: 복구 엔진이 반환한 Mapping 결과 객체.
        - webhook_url: Slack Incoming Webhook HTTPS 엔드포인트 URL 문자열.
        - timeout: 네트워크 요청 제한 시간 (초, 기본값 3.0초).
    """
    target_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL")
    if not target_url:
        logger.warning(
            "Slack Webhook URL이 설정되지 않아 3차 복구 알림 전송을 건너뜁니다 (id=%s)",
            report.incident_id,
        )
        return False

    try:
        parsed = urllib.parse.urlparse(target_url)
        if not (parsed.scheme == "https" and parsed.netloc):
            logger.warning(
                "유효하지 않은 Slack Webhook HTTPS URL입니다: %s",
                _mask_webhook_url(target_url),
            )
            return False
    except Exception as exc:
        logger.warning("유효하지 않은 Slack Webhook URL 형식입니다: %s", type(exc).__name__)
        return False

    try:
        payload = build_recovery_slack_payload(report, recovery_result)
        encoded_data = json.dumps(payload).encode("utf-8")
    except Exception as exc:
        logger.error("3차 복구 Slack Block Kit 페이로드 직렬화 실패: %s", exc)
        return False

    start_time = time.monotonic()
    for attempt in range(max_retries + 1):
        elapsed = time.monotonic() - start_time
        remaining_budget = timeout - elapsed
        if remaining_budget <= 0:
            logger.error(
                "3차 복구 Slack Webhook 시간 예산 소진으로 전송 중단 (시도: %d)",
                attempt + 1,
            )
            return False

        req_timeout = timeout if (attempt == 0 and elapsed < 0.05) else remaining_budget
        try:
            req = urllib.request.Request(
                url=target_url,
                data=encoded_data,
                headers={"Content-Type": "application/json; charset=utf-8"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=req_timeout) as response:
                status_code = getattr(response, "status", None) or response.getcode()
                if status_code == 200:
                    logger.info(
                        "3차 복구 Slack 알림 전송 성공: %s (시도: %d)",
                        report.incident_id,
                        attempt + 1,
                    )
                    return True
                logger.warning(
                    "3차 복구 Slack Webhook 비정상 응답 코드: %s (시도: %d)",
                    status_code,
                    attempt + 1,
                )
                if status_code < 500:
                    return False
        except urllib.error.HTTPError as exc:
            logger.error(
                "3차 복구 Slack Webhook HTTP 오류 (코드: %s, 유형: %s, 시도: %d)",
                exc.code,
                type(exc).__name__,
                attempt + 1,
            )
            if exc.code < 500:
                return False
        except TimeoutError:
            logger.error("3차 복구 Slack Webhook 요청 시간 초과 (timeout=%.2f초)", req_timeout)
            return False
        except urllib.error.URLError as exc:
            logger.error(
                "3차 복구 Slack Webhook 연결 실패 (유형: %s, 시도: %d)",
                type(getattr(exc, "reason", exc)).__name__,
                attempt + 1,
            )
        except Exception as exc:
            # InvalidURL 등 일반 예외 시 URL/토큰이 포함될 수 있는 exc 원문 노출 차단
            logger.error(
                "3차 복구 Slack Webhook 전송 중 오류 발생 (유형: %s, 시도: %d)",
                type(exc).__name__,
                attempt + 1,
            )
            return False

        if attempt < max_retries:
            remaining_before_sleep = timeout - (time.monotonic() - start_time)
            if remaining_before_sleep <= 0:
                return False
            time.sleep(min(retry_delay, remaining_before_sleep))

    logger.error("3차 복구 Slack Webhook 최대 재시도 초과로 최종 실패 격리")
    return False
