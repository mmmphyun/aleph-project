# CloudShield 단위 테스트: Slack 알림 모듈
# 소유자: 클라우드 B 담당
"""Slack Block Kit 알림 전송기(slack_notifier.py) 단위 테스트."""

from __future__ import annotations

import pytest

from contracts.incident import IncidentReport
from reporter.slack_notifier import send_slack_alert


def test_send_slack_alert_interface(sample_incident_report: IncidentReport) -> None:
    """send_slack_alert 함수 시그니처 및 스켈레톤 인터페이스 스모크 검증.

    Why:
        클라우드 B 담당 에이전트가 slack_notifier.py 구현 착수 전 모듈 import 경로와
        함수 시그니처(IncidentReport 인자 수락 여부)를 즉각 검증함.
    """
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/XXXX"
    with pytest.raises(NotImplementedError, match="클라우드 B 담당자 구현 영역"):
        send_slack_alert(sample_incident_report, dummy_webhook)


@pytest.mark.skip(reason="클라우드 B 구현 대기")
def test_send_slack_alert_success(
    sample_incident_report: IncidentReport, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Slack Incoming Webhook Block Kit 카드 전송 성공 검증."""
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/XXXX"
    result = send_slack_alert(sample_incident_report, dummy_webhook)
    assert result is True
