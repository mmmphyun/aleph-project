# 클라우드 B 전용 모듈: Slack Block Kit 상황 전파(slack_notifier.py)
# 소유자: 클라우드 B
"""Slack Block Kit 알림 카드 생성 및 전파 모듈 패키지 인터페이스."""

from reporter.slack_notifier import (
    MAX_FIELD_LENGTH,
    MAX_HEADER_LENGTH,
    build_slack_payload,
    build_waf_slack_payload,
    send_slack_alert,
    truncate_text,
)

__all__ = [
    "MAX_FIELD_LENGTH",
    "MAX_HEADER_LENGTH",
    "build_slack_payload",
    "build_waf_slack_payload",
    "send_slack_alert",
    "truncate_text",
]
