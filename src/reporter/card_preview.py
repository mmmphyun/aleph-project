"""실제 전송·복구 없이 동일 사건의 3단계 Slack 렌더링을 재현한다."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from contracts.incident import IncidentReport
from reporter.slack_notifier import (
    build_llm_slack_payload,
    build_recovery_slack_payload,
    build_slack_payload,
)


def build_three_stage_preview(
    report: IncidentReport,
    remediation_result: Mapping[str, Any],
    recovery_result: Mapping[str, Any],
) -> dict[str, Any]:
    """기존 카드 빌더로 탐지·분석·복구 순서의 로컬 검토 자료를 반환한다.

    Why: 운영 Slack에 합성 사고를 보내지 않고 사건 연계와 전문 표시를 검증한다.
    Constraints: 결과는 주입된 관측값이며 실제 API 성공이나 게시 순서 증거가 아니다.
        LLM 분석 자체는 수행하지 않는다. 분석할 보고서는 호출자가 전달한다.
    Side-effects: 외부 통신·파일 쓰기·계약 변경 없음. 카드 상한 오류는 그대로 전파한다.
    """
    return {
        "evidence_kind": "local_render_only",
        "slack_delivery_verified": False,
        "infrastructure_recovery_verified": False,
        "cards": [
            {"stage": 1, "payload": build_slack_payload(report, dict(remediation_result))},
            {"stage": 2, "payload": build_llm_slack_payload(report)},
            {"stage": 3, "payload": build_recovery_slack_payload(report, recovery_result)},
        ],
    }
