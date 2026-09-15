# CloudShield 단위 테스트: Slack 알림 모듈
# 소유자: 클라우드 B 담당
"""Slack Block Kit 알림 전송기(slack_notifier.py) 단위 테스트.

Why:
    보안 사고 분석 보고서(IncidentReport)가 주어졌을 때 Slack Block Kit 카드가 규격에 맞게
    안전하게 생성되는지, 500자 자르기 방어 로직 및 Webhook 통신 예외 격리가 온전히 동작하는지
    검증함.
"""

from __future__ import annotations

import io
import json
import urllib.error
from typing import Any
from unittest.mock import MagicMock

import pytest

from contracts.incident import IncidentReport
from reporter.slack_notifier import (
    MAX_FIELD_LENGTH,
    build_slack_payload,
    send_slack_alert,
    truncate_text,
)


def test_truncate_text_within_limit() -> None:
    """제한 길이 이하의 텍스트는 원본 그대로 유지됨을 검증."""
    text = "정상적인 길이의 보안 경보 요약문입니다."
    assert truncate_text(text, 500) == text


def test_truncate_text_exceeding_limit() -> None:
    """500자를 초과하는 긴 텍스트는 500자로 잘리고 말줄임표(...)가 붙는지 검증.

    Why:
        Slack Block Kit API의 텍스트 길이 초과(HTTP 400 invalid_payload)를 방지하기 위함.
    """
    long_text = "A" * 600
    truncated = truncate_text(long_text, MAX_FIELD_LENGTH)
    assert len(truncated) == 500
    assert truncated.endswith("...")
    assert truncated.startswith("A" * 497)


def test_truncate_text_edge_cases() -> None:
    """길이 제한이 매우 작거나 동일한 경우의 엣지 케이스 검증."""
    assert truncate_text("hello", 5) == "hello"
    assert truncate_text("hello", 3) == "hel"
    assert truncate_text("hello", 2) == "he"


def test_build_slack_payload_required_keys(sample_incident_report: IncidentReport) -> None:
    """생성된 Slack Block Kit 페이로드에 4대 필수 키가 정확히 포함되는지 검증.

    Why:
        헌법 5.1-3 표준: Slack Block Kit 카드 페이로드 작성 시 필수 키
        (incident_id, rule_name, source_ip, remediation_action) 누락 방지.
    """
    payload = build_slack_payload(sample_incident_report)

    # 1. 딕셔너리 필수 키 검증
    assert "incident_id" in payload
    assert "rule_name" in payload
    assert "source_ip" in payload
    assert "remediation_action" in payload

    assert payload["incident_id"] == sample_incident_report.incident_id
    assert payload["rule_name"] == sample_incident_report.attack_type
    assert payload["source_ip"] == sample_incident_report.source_ip
    assert payload["remediation_action"] == sample_incident_report.action_required

    # 2. Block Kit UI 구조 검증
    assert "blocks" in payload
    blocks = payload["blocks"]
    assert len(blocks) >= 6

    # 3. fields 블록 내 4대 필수 식별자 표현 검증
    section_with_fields = next(b for b in blocks if b.get("type") == "section" and "fields" in b)
    fields_texts = [f["text"] for f in section_with_fields["fields"]]
    joined_fields = " ".join(fields_texts)

    assert "incident_id" in joined_fields
    assert sample_incident_report.incident_id in joined_fields
    assert "rule_name" in joined_fields
    assert sample_incident_report.attack_type in joined_fields
    assert "source_ip" in joined_fields
    assert sample_incident_report.source_ip in joined_fields
    assert "remediation_action" in joined_fields
    assert sample_incident_report.action_required in joined_fields


def test_build_slack_payload_truncation() -> None:
    """초과 길이의 필드가 포함된 IncidentReport에서도 페이로드가 안전하게 잘리는지 검증."""
    long_summary = "공격 탐지 상세: " + ("긴 텍스트 " * 100)
    report = IncidentReport(
        incident_id="INC-20260915-999",
        attack_type="T" * 600,
        mitre_id="T1110.001",
        risk_level="HIGH",
        source_ip="203.0.113.10",
        target_identifier="i-1234567890abcdef0",
        target_accounts=("admin",),
        summary_ko=long_summary,
        action_required="BLOCK_WAF",
        recommendations=("R" * 600,),
    )

    payload = build_slack_payload(report)
    summary_block = next(
        b
        for b in payload["blocks"]
        if b.get("type") == "section" and "*사고 요약:*" in b.get("text", {}).get("text", "")
    )
    summary_content = summary_block["text"]["text"]
    assert "..." in summary_content
    assert len(payload["text"]) <= 600


def test_build_slack_payload_empty_targets_and_recommendations(
    sample_incident_data: dict[str, Any],
) -> None:
    """target_accounts와 recommendations가 빈 튜플인 경우에도 레이아웃 무결성이 유지되는지 검증."""
    data = dict(sample_incident_data)
    data["target_accounts"] = []
    data["recommendations"] = []
    report = IncidentReport.model_validate(data)

    payload = build_slack_payload(report)
    blocks = payload["blocks"]

    # 계정 섹션 기본 문구 확인
    account_block = next(
        b
        for b in blocks
        if b.get("type") == "section" and "*공격 대상 계정:*" in b.get("text", {}).get("text", "")
    )
    assert "없음 (단일 호스트 스캔)" in account_block["text"]["text"]

    # 권고 섹션 기본 문구 확인
    rec_block = next(
        b
        for b in blocks
        if b.get("type") == "section" and "*SecOps 권고 조치:*" in b.get("text", {}).get("text", "")
    )
    assert "별도 권고 조치 없음 (대응 완료)" in rec_block["text"]["text"]


@pytest.mark.parametrize(
    ("risk_level", "expected_emoji"),
    [
        ("HIGH", "🚨"),
        ("MEDIUM", "⚠️"),
        ("LOW", "ℹ️"),
    ],
)
def test_build_slack_payload_risk_emojis(
    sample_incident_data: dict[str, Any],
    risk_level: str,
    expected_emoji: str,
) -> None:
    """사고 위험도(HIGH/MEDIUM/LOW)별로 헤더 이모지가 올바르게 매핑되는지 검증."""
    data = dict(sample_incident_data)
    data["risk_level"] = risk_level
    report = IncidentReport.model_validate(data)

    payload = build_slack_payload(report)
    header_block = payload["blocks"][0]
    assert expected_emoji in header_block["text"]["text"]


def test_send_slack_alert_invalid_url(sample_incident_report: IncidentReport) -> None:
    """유효하지 않은 Webhook URL(HTTP 또는 스킴 누락) 전달 시 즉시 False를 반환하는지 검증."""
    assert send_slack_alert(sample_incident_report, "http://insecure.slack.com/webhook") is False
    assert send_slack_alert(sample_incident_report, "invalid-url") is False
    assert send_slack_alert(sample_incident_report, "") is False


def test_send_slack_alert_success(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slack Webhook 정상 200 응답 수신 시 True 반환 및 페이로드 전송 검증."""
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/VALID"

    mock_response = MagicMock()
    mock_response.getcode.return_value = 200
    mock_response.status = 200
    mock_response.__enter__.return_value = mock_response
    mock_response.__exit__.return_value = None

    captured_requests: list[urllib.request.Request] = []

    def mock_urlopen(req: urllib.request.Request, timeout: float = 5.0) -> MagicMock:
        captured_requests.append(req)
        return mock_response

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(sample_incident_report, dummy_webhook, timeout=3.0)
    assert result is True
    assert len(captured_requests) == 1

    req = captured_requests[0]
    assert req.full_url == dummy_webhook
    assert req.get_method() == "POST"
    assert req.headers["Content-type"] == "application/json; charset=utf-8"

    body_json = json.loads(req.data.decode("utf-8"))
    assert body_json["incident_id"] == sample_incident_report.incident_id


def test_send_slack_alert_http_error(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slack Webhook 400/404/429/500 HTTPError 발생 시 False 반환 및 예외 격리 검증."""
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/ERROR"

    def mock_urlopen(req: urllib.request.Request, timeout: float = 5.0) -> MagicMock:
        raise urllib.error.HTTPError(
            url=dummy_webhook,
            code=400,
            msg="Bad Request",
            hdrs=MagicMock(),  # type: ignore[arg-type]
            fp=io.BytesIO(b"invalid_payload"),
        )

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(sample_incident_report, dummy_webhook)
    assert result is False


def test_send_slack_alert_url_error_and_timeout(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """네트워크 단절(URLError) 또는 타임아웃 발생 시 안전하게 False를 반환하는지 검증."""
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/TIMEOUT"

    def mock_urlopen_timeout(req: urllib.request.Request, timeout: float = 5.0) -> MagicMock:
        raise TimeoutError("Connection timed out")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen_timeout)
    assert send_slack_alert(sample_incident_report, dummy_webhook) is False

    def mock_urlopen_url_error(req: urllib.request.Request, timeout: float = 5.0) -> MagicMock:
        raise urllib.error.URLError("DNS lookup failed")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen_url_error)
    assert send_slack_alert(sample_incident_report, dummy_webhook) is False
