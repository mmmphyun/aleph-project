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
import time
import urllib.error
from typing import Any
from unittest.mock import MagicMock

import pytest

from contracts.incident import IncidentReport
from reporter.slack_notifier import (
    MAX_FIELD_LENGTH,
    MAX_HEADER_LENGTH,
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
    assert len(summary_content) <= MAX_FIELD_LENGTH
    assert len(payload["text"]) <= MAX_FIELD_LENGTH


def test_build_slack_payload_all_display_strings_length_limit() -> None:
    """긴 식별자(incident_id 2,100자, mitre_id 3,100자) 및 초과 필드의 최종 표시 문자열 검증.

    Why:
        Slack Block Kit의 필드당 2,000자 / 텍스트 3,000자 초과를 방지하고 프로젝트의
        필드별 500자(헤더 150자) 안전 기준을 최종 표시 문자열(라벨/마크다운 포함) 단위로 보장함.
    """
    long_incident_id = "INC-" + "A" * 2100
    long_mitre_id = "T" + "B" * 3100
    long_attack_type = "BruteForce-" + "C" * 1000
    long_summary = "공격 요약 내용 " + "D" * 1000
    long_accounts = tuple(f"user_{idx}_{'E' * 50}" for idx in range(30))
    long_recommendations = tuple(f"조치 권고안 {idx}: {'F' * 100}" for idx in range(20))

    report = IncidentReport(
        incident_id=long_incident_id,
        attack_type=long_attack_type,
        mitre_id=long_mitre_id,
        risk_level="HIGH",
        source_ip="198.51.100.254",
        target_identifier="i-abcdef01234567890",
        target_accounts=long_accounts,
        summary_ko=long_summary,
        action_required="QUARANTINE_EC2",
        recommendations=long_recommendations,
    )

    payload = build_slack_payload(report)

    # 1. 4대 필수 키 구조화 데이터는 원본 무결성 보존 검증
    assert payload["incident_id"] == long_incident_id
    assert payload["rule_name"] == long_attack_type
    assert payload["source_ip"] == "198.51.100.254"
    assert payload["remediation_action"] == "QUARANTINE_EC2"

    # 2. 최상위 fallback text 길이 검증 (500자 이하)
    assert len(payload["text"]) <= MAX_FIELD_LENGTH
    assert payload["text"].endswith("...")

    # 3. 모든 블록 내 최종 표시 문자열 길이 검증
    for block in payload["blocks"]:
        block_type = block.get("type")

        # 헤더 텍스트 검증 (Slack 규격 150자 이내)
        if block_type == "header":
            header_text = block["text"]["text"]
            assert len(header_text) <= MAX_HEADER_LENGTH

        # 섹션 단일 텍스트 검증 (프로젝트 500자 이내 및 Slack 규격 3,000자 이내)
        if block_type == "section" and "text" in block:
            section_text = block["text"]["text"]
            assert len(section_text) <= MAX_FIELD_LENGTH
            assert len(section_text) <= 3000

        # 섹션 fields 검증 (프로젝트 500자 이내 및 Slack 규격 2,000자 이내)
        if block_type == "section" and "fields" in block:
            for field in block["fields"]:
                field_text = field["text"]
                assert len(field_text) <= MAX_FIELD_LENGTH
                assert len(field_text) <= 2000

        # context elements 검증 (프로젝트 500자 이내 및 Slack 규격 3,000자 이내)
        if block_type == "context" and "elements" in block:
            for elem in block["elements"]:
                elem_text = elem["text"]
                assert len(elem_text) <= MAX_FIELD_LENGTH
                assert len(elem_text) <= 3000

    # 4. 긴 incident_id, mitre_id, 요약, 공격유형 필드의 구체적 상한 및 말줄임표 검증
    fields_section = next(
        b for b in payload["blocks"] if b.get("type") == "section" and "fields" in b
    )
    incident_id_field = next(f["text"] for f in fields_section["fields"] if "*사건 ID" in f["text"])
    attack_type_field = next(
        f["text"] for f in fields_section["fields"] if "*공격 유형" in f["text"]
    )

    assert len(incident_id_field) <= MAX_FIELD_LENGTH
    assert incident_id_field.endswith("...")

    assert len(attack_type_field) <= MAX_FIELD_LENGTH
    assert attack_type_field.endswith("...")

    summary_section = next(
        b
        for b in payload["blocks"]
        if b.get("type") == "section" and "*사고 요약" in b.get("text", {}).get("text", "")
    )
    assert len(summary_section["text"]["text"]) <= MAX_FIELD_LENGTH
    assert summary_section["text"]["text"].endswith("...")

    context_block = next(b for b in payload["blocks"] if b.get("type") == "context")
    context_elem_text = context_block["elements"][0]["text"]
    assert len(context_elem_text) <= MAX_FIELD_LENGTH
    assert context_elem_text.endswith("...")


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
    """유효하지 않은 Webhook URL(HTTP, 스킴 누락, 비정상 IPv6) 전달 시 False 반환 검증."""
    assert send_slack_alert(sample_incident_report, "http://insecure.slack.com/webhook") is False
    assert send_slack_alert(sample_incident_report, "invalid-url") is False
    assert send_slack_alert(sample_incident_report, "") is False
    assert send_slack_alert(sample_incident_report, "https://[invalid") is False


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


def test_send_slack_alert_direct_timeout_immediate_exit(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """직접적인 TimeoutError 발생 시 재시도 없이 1회 호출만에 즉시 False 반환 검증.

    Why:
        3초 타임아웃 발생 후 재시도(3초 + 0.5초 + 3초 = 6.5초)를 진행하면
        E2E 파이프라인 10초 관통 SLA를 위협하므로 1회 타임아웃 시 즉시 종료해야 함.
    """
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/DIRECT_TIMEOUT"
    call_count = 0

    def mock_urlopen(req: urllib.request.Request, timeout: float = 3.0) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise TimeoutError("The read operation timed out")

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(
        sample_incident_report,
        dummy_webhook,
        timeout=3.0,
        max_retries=1,
        retry_delay=0.5,
    )
    assert result is False
    assert call_count == 1, "타임아웃 발생 시 재시도 없이 1회만에 즉시 종료되어야 함"


def test_send_slack_alert_url_error_wrapped_timeout_immediate_exit(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """URLError로 래핑된 TimeoutError 발생 시 1회 호출만에 즉시 False 반환 검증.

    Why:
        urllib.request는 네트워크 타임아웃 시 URLError(reason=TimeoutError) 형태로
        예외를 감싸서 발생시킬 수 있으므로 동일하게 재시도 없이 즉시 종료되어야 함.
    """
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/WRAPPED_TIMEOUT"
    call_count = 0

    def mock_urlopen(req: urllib.request.Request, timeout: float = 3.0) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise urllib.error.URLError(TimeoutError("timed out"))

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(
        sample_incident_report,
        dummy_webhook,
        timeout=3.0,
        max_retries=1,
        retry_delay=0.5,
    )
    assert result is False
    assert call_count == 1, "URLError(TimeoutError) 발생 시 즉시 종료되어야 함"


def test_send_slack_alert_delayed_5xx_cumulative_time_budget(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """지연된 5xx 응답 시 전체 시간 예산(3초)을 공유하여 남은 예산에 맞춰 호출/중단 검증.

    Why:
        1차 시도가 2.8초 지연된 후 503 에러가 발생한 경우, 0.5초 대기와 3초 재시도를
        그대로 수행하면 6.3초가 소요되므로 남은 예산(0.2초) 내에서 처리되거나 차단되어야 함.
    """
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/DELAYED_5XX"
    call_count = 0
    simulated_current_time = 100.0

    def mock_monotonic() -> float:
        return simulated_current_time

    def mock_sleep(seconds: float) -> None:
        nonlocal simulated_current_time
        simulated_current_time += seconds

    def mock_urlopen(req: urllib.request.Request, timeout: float = 3.0) -> MagicMock:
        nonlocal call_count, simulated_current_time
        call_count += 1
        # 1차 시도에서 2.8초가 소요된 후 503 반환
        simulated_current_time += 2.8
        raise urllib.error.HTTPError(
            url=dummy_webhook,
            code=503,
            msg="Service Unavailable",
            hdrs=MagicMock(),  # type: ignore[arg-type]
            fp=io.BytesIO(b"transient_delay"),
        )

    monkeypatch.setattr(time, "monotonic", mock_monotonic)
    monkeypatch.setattr(time, "sleep", mock_sleep)
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(
        sample_incident_report,
        dummy_webhook,
        timeout=3.0,
        max_retries=1,
        retry_delay=0.5,
    )

    assert result is False
    # 2.8초 소요 후 남은 대기 시간은 min(0.5, 0.2) = 0.2초로 제한되고,
    # 그 후 시간 예산(3.0초) 소진으로 2차 시도 없이 안전하게 격리됨
    assert call_count == 1
    assert simulated_current_time <= 103.001, "총 실행 시간은 3.0초 예산을 초과하지 않아야 함"


def test_send_slack_alert_time_budget_shared_across_retries(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """1차 시도에서 1.0초 지연 후 503 발생 시 잔여 예산 전달 검증.

    Why:
        2차 시도에 잔여 예산(1.5초)이 timeout 인자로 정확히 계산되어 전달되는지 확인함.
    """
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/SHARED_BUDGET"
    captured_timeouts: list[float] = []
    simulated_current_time = 100.0

    def mock_monotonic() -> float:
        return simulated_current_time

    def mock_sleep(seconds: float) -> None:
        nonlocal simulated_current_time
        simulated_current_time += seconds

    mock_success_response = MagicMock()
    mock_success_response.getcode.return_value = 200
    mock_success_response.status = 200
    mock_success_response.__enter__.return_value = mock_success_response
    mock_success_response.__exit__.return_value = None

    def mock_urlopen(req: urllib.request.Request, timeout: float = 3.0) -> MagicMock:
        nonlocal simulated_current_time
        captured_timeouts.append(timeout)
        if len(captured_timeouts) == 1:
            simulated_current_time += 1.0  # 1차 시도 1.0초 소요
            raise urllib.error.HTTPError(
                url=dummy_webhook,
                code=503,
                msg="Service Unavailable",
                hdrs=MagicMock(),  # type: ignore[arg-type]
                fp=io.BytesIO(b"transient_error"),
            )
        return mock_success_response

    monkeypatch.setattr(time, "monotonic", mock_monotonic)
    monkeypatch.setattr(time, "sleep", mock_sleep)
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(
        sample_incident_report,
        dummy_webhook,
        timeout=3.0,
        max_retries=1,
        retry_delay=0.5,
    )

    assert result is True
    assert len(captured_timeouts) == 2
    assert captured_timeouts[0] == 3.0
    # 3.0초 예산에서 1.0초(요청) + 0.5초(대기) = 1.5초 경과 후 잔여 1.5초 전달 확인
    assert abs(captured_timeouts[1] - 1.5) < 0.01


def test_send_slack_alert_invalid_ipv6_url_regression(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """비정상 IPv6 대괄호 URL 전달 시 ValueError 예외 격리 및 urlopen 미호출 회귀 검증.

    Why:
        urlparse()에서 잘못된 IPv6 URL 파싱 시 발생하는 ValueError가 호출자에게 전파되지 않고
        안전하게 False를 반환하는 예외 격리(Fault Tolerance)를 보장함.
    """
    mock_urlopen = MagicMock()
    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    invalid_ipv6_url = "https://[invalid"
    result = send_slack_alert(sample_incident_report, invalid_ipv6_url)

    assert result is False
    mock_urlopen.assert_not_called()


def test_build_slack_payload_with_remediation_result_success(
    sample_incident_report: IncidentReport,
) -> None:
    """오케스트레이터 RemediationResult(성공) 전달 시 차단 집행 현황 섹션 렌더링 검증.

    Why:
        오케스트레이터가 집행한 L4 격리 및 L7 WAF 차단 성공 상태를 Slack 카드로 시각화하여
        SecOps 관리자 채널에 침해 사고 차단 완료 상태를 명확히 전파함.
    """
    remediation_res = {
        "waf_blocked": True,
        "quarantine_applied": True,
        "iam_revoked": False,
    }
    payload = build_slack_payload(sample_incident_report, remediation_result=remediation_res)

    # 1. 4대 필수 키 및 remediation_result 구조화 데이터 검증
    assert payload["incident_id"] == sample_incident_report.incident_id
    assert payload["rule_name"] == sample_incident_report.attack_type
    assert payload["source_ip"] == sample_incident_report.source_ip
    assert payload["remediation_action"] == sample_incident_report.action_required
    assert payload["remediation_result"] == {
        "waf_blocked": True,
        "quarantine_applied": True,
        "iam_revoked": False,
    }

    # 2. Block Kit UI 내 차단 집행 현황 블록 존재 및 내용 검증
    blocks = payload["blocks"]
    remediation_block = next(
        (
            b
            for b in blocks
            if "*인프라 원자적 차단 집행 현황:*" in b.get("text", {}).get("text", "")
        ),
        None,
    )
    assert remediation_block is not None
    block_text = remediation_block["text"]["text"]
    assert "• L4 EC2 네트워크 격리: ✅ 격리 성공 (SG 전면 차단)" in block_text
    assert "• L7 WAFv2 IP 차단: ✅ IPSet 차단 완료 (/32)" in block_text
    assert "• Identity IAM 세션 무효화: ℹ️ 미대상 (SSH 시나리오 제외)" in block_text


def test_build_slack_payload_with_partial_remediation_failure(
    sample_incident_report: IncidentReport,
) -> None:
    """차단 조치 중 요청된 조치(BLOCK_AND_QUARANTINE)가 실패한 경우의 UI 렌더링 검증.

    Why:
        요청된 액션(L4 격리, L7 차단)의 실패는 '실패/미완료'로 표시되어야 하며,
        정상/미적용으로 잘못 표시되어 관제 판단을 흐리지 않도록 보장함.
    """
    remediation_res = {
        "waf_blocked": False,
        "quarantine_applied": False,
        "iam_revoked": False,
    }
    payload = build_slack_payload(sample_incident_report, remediation_result=remediation_res)

    remediation_block = next(
        b
        for b in payload["blocks"]
        if "*인프라 원자적 차단 집행 현황:*" in b.get("text", {}).get("text", "")
    )
    block_text = remediation_block["text"]["text"]
    assert "• L4 EC2 네트워크 격리: ❌ 격리 실패 / 미완료" in block_text
    assert "• L7 WAFv2 IP 차단: ❌ 차단 실패 / 미완료" in block_text
    assert "• Identity IAM 세션 무효화: ℹ️ 미대상 (SSH 시나리오 제외)" in block_text


def test_build_slack_payload_with_iam_requested_failure(
    sample_incident_data: dict[str, Any],
) -> None:
    """REVOKE_IAM_SESSION 액션 요청 시 IAM 세션 무효화 실패 및 L4/L7 미대상 표시 검증.

    Why:
        IAM 세션 취소가 지시된 경우 미완료는 실패로 표시되고,
        네트워크 격리나 WAF 차단은 미대상으로 명확히 구분되어야 함.
    """
    data = dict(sample_incident_data)
    data["action_required"] = "REVOKE_IAM_SESSION"
    data["attack_type"] = "IAM Credential Abuse"
    report = IncidentReport.model_validate(data)

    remediation_res = {
        "waf_blocked": False,
        "quarantine_applied": False,
        "iam_revoked": False,
    }
    payload = build_slack_payload(report, remediation_result=remediation_res)

    remediation_block = next(
        b
        for b in payload["blocks"]
        if "*인프라 원자적 차단 집행 현황:*" in b.get("text", {}).get("text", "")
    )
    block_text = remediation_block["text"]["text"]
    assert "• L4 EC2 네트워크 격리: ℹ️ 격리 미대상" in block_text
    assert "• L7 WAFv2 IP 차단: ℹ️ 차단 미대상" in block_text
    assert "• Identity IAM 세션 무효화: ❌ 세션 무효화 실패 / 미완료" in block_text


def test_build_slack_payload_with_non_target_and_waf_only(
    sample_incident_data: dict[str, Any],
) -> None:
    """BLOCK_WAF 요청 시 WAF 성공 및 L4/IAM 미대상 표시 검증."""
    data = dict(sample_incident_data)
    data["action_required"] = "BLOCK_WAF"
    report = IncidentReport.model_validate(data)

    remediation_res = {
        "waf_blocked": True,
        "quarantine_applied": False,
        "iam_revoked": False,
    }
    payload = build_slack_payload(report, remediation_result=remediation_res)

    remediation_block = next(
        b
        for b in payload["blocks"]
        if "*인프라 원자적 차단 집행 현황:*" in b.get("text", {}).get("text", "")
    )
    block_text = remediation_block["text"]["text"]
    assert "• L4 EC2 네트워크 격리: ℹ️ 격리 미대상" in block_text
    assert "• L7 WAFv2 IP 차단: ✅ IPSet 차단 완료 (/32)" in block_text
    assert "• Identity IAM 세션 무효화: ℹ️ 미대상 (SSH 시나리오 제외)" in block_text


def test_send_slack_alert_default_timeout_is_three_seconds(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """send_slack_alert의 기본 타임아웃이 3.0초로 지정되어 호출되는지 검증.

    Why:
        10초 관통 SLA 파이프라인에서 슬랙 알림 단계의 지연 상한을 3초로 강제함.
    """
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/VALID"
    captured_timeouts: list[float] = []

    mock_response = MagicMock()
    mock_response.getcode.return_value = 200
    mock_response.status = 200
    mock_response.__enter__.return_value = mock_response
    mock_response.__exit__.return_value = None

    def mock_urlopen(req: urllib.request.Request, timeout: float = 3.0) -> MagicMock:
        captured_timeouts.append(timeout)
        return mock_response

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(sample_incident_report, dummy_webhook)
    assert result is True
    assert captured_timeouts == [3.0]


def test_send_slack_alert_transient_5xx_retry_and_recovery(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slack API 일시적 503 오류 발생 시 1회 재시도 후 성공 처리 및 예외 격리 검증.

    Why:
        외부 Webhook의 일시적 서버 오류(5xx) 시 즉시 실패하지 않고 1회 안전 재시도하여
        알림 전파 성공률을 높이면서도 메인 런타임에 부하를 주지 않음.
    """
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/RETRY"
    call_count = 0

    mock_success_response = MagicMock()
    mock_success_response.getcode.return_value = 200
    mock_success_response.status = 200
    mock_success_response.__enter__.return_value = mock_success_response
    mock_success_response.__exit__.return_value = None

    def mock_urlopen(req: urllib.request.Request, timeout: float = 3.0) -> MagicMock:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise urllib.error.HTTPError(
                url=dummy_webhook,
                code=503,
                msg="Service Unavailable",
                hdrs=MagicMock(),  # type: ignore[arg-type]
                fp=io.BytesIO(b"transient_error"),
            )
        return mock_success_response

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(
        sample_incident_report,
        dummy_webhook,
        timeout=3.0,
        max_retries=1,
        retry_delay=0.01,
    )
    assert result is True
    assert call_count == 2


def test_send_slack_alert_5xx_retry_exhausted_isolation(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """지속적인 HTTP 500 오류 시 재시도 소진 후 예외 없이 안전하게 False를 반환하는지 검증."""
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/500_ERROR"
    call_count = 0

    def mock_urlopen(req: urllib.request.Request, timeout: float = 3.0) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise urllib.error.HTTPError(
            url=dummy_webhook,
            code=500,
            msg="Internal Server Error",
            hdrs=MagicMock(),  # type: ignore[arg-type]
            fp=io.BytesIO(b"server_crash"),
        )

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(
        sample_incident_report,
        dummy_webhook,
        timeout=3.0,
        max_retries=1,
        retry_delay=0.01,
    )
    assert result is False
    assert call_count == 2


def test_send_slack_alert_client_4xx_no_retry(
    sample_incident_report: IncidentReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP 400 Bad Request 등의 클라이언트 오류는 재시도 없이 1회만에 즉시 False 반환 검증."""
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/400_ERROR"
    call_count = 0

    def mock_urlopen(req: urllib.request.Request, timeout: float = 3.0) -> MagicMock:
        nonlocal call_count
        call_count += 1
        raise urllib.error.HTTPError(
            url=dummy_webhook,
            code=400,
            msg="Bad Request",
            hdrs=MagicMock(),  # type: ignore[arg-type]
            fp=io.BytesIO(b"bad_request"),
        )

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(
        sample_incident_report,
        dummy_webhook,
        timeout=3.0,
        max_retries=1,
        retry_delay=0.01,
    )
    assert result is False
    assert call_count == 1


def test_send_slack_alert_orchestrator_integration_mock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """오케스트레이터(threat_orchestrator_handler) 연계 모의 입력 기반 전체 알림 전송 검증.

    Why:
        오케스트레이터에서 생성하는 SSH Brute Force IncidentReport 및 Boto3 원자적 차단
        RemediationResult가 결합된 실제 상황을 모의하여 전파 파이프라인의 종단 간 정합성을 검증함.
    """
    dummy_webhook = "https://hooks.slack.com/services/T000/B000/ORCHESTRATOR"

    orchestrator_report = IncidentReport(
        incident_id="INC-1727078400-0050",
        attack_type="SSH Brute Force",
        mitre_id="T1110.001",
        risk_level="HIGH",
        source_ip="198.51.100.50",
        target_identifier="i-0abcd1234ef567890",
        target_accounts=("admin",),
        summary_ko=(
            "동일 IP(198.51.100.50) 및 계정(admin)에 대한 "
            "5분 내 5회 이상 분할 누적 무차별 대입 공격이 탐지되었습니다."
        ),
        action_required="BLOCK_AND_QUARANTINE",
        recommendations=(
            "L4 보안 그룹 전면 격리 상태 유지",
            "WAF IPSet /32 단일 호스트 차단 등록 확인",
        ),
    )

    orchestrator_remediation: dict[str, Any] = {
        "waf_blocked": True,
        "quarantine_applied": True,
        "iam_revoked": False,
    }

    mock_response = MagicMock()
    mock_response.getcode.return_value = 200
    mock_response.status = 200
    mock_response.__enter__.return_value = mock_response
    mock_response.__exit__.return_value = None

    captured_requests: list[urllib.request.Request] = []

    def mock_urlopen(req: urllib.request.Request, timeout: float = 3.0) -> MagicMock:
        captured_requests.append(req)
        return mock_response

    monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

    result = send_slack_alert(
        report=orchestrator_report,
        webhook_url=dummy_webhook,
        timeout=3.0,
        remediation_result=orchestrator_remediation,
    )

    assert result is True
    assert len(captured_requests) == 1

    req = captured_requests[0]
    payload = json.loads(req.data.decode("utf-8"))

    # 4대 필수 키 및 오케스트레이터 규격 일치 확인
    assert payload["incident_id"] == "INC-1727078400-0050"
    assert payload["rule_name"] == "SSH Brute Force"
    assert payload["source_ip"] == "198.51.100.50"
    assert payload["remediation_action"] == "BLOCK_AND_QUARANTINE"

    # remediation_result 모델 키 일치 확인
    assert payload["remediation_result"]["waf_blocked"] is True
    assert payload["remediation_result"]["quarantine_applied"] is True
    assert payload["remediation_result"]["iam_revoked"] is False

    # Block Kit UI 내 차단 상태 텍스트 존재 확인
    remediation_section = next(
        b
        for b in payload["blocks"]
        if "*인프라 원자적 차단 집행 현황:*" in b.get("text", {}).get("text", "")
    )
    assert "✅ 격리 성공 (SG 전면 차단)" in remediation_section["text"]["text"]
    assert "✅ IPSet 차단 완료 (/32)" in remediation_section["text"]["text"]
