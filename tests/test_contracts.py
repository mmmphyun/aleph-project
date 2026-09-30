# CloudShield 인터페이스 계약 검증 테스트
# 소유자: 클라우드 A
"""Pydantic V2 데이터 계약 모델 및 Mock 데이터 정합성 검증 테스트."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.events import (
    CloudWatchLogsPayload,
    NginxAccessLogEvent,
    SyslogAuthEvent,
)
from contracts.incident import IncidentReport
from detection.incident_mapper import _RULE_METADATA, map_threat_to_incident
from detection.rules import (
    AUTH_FAILURE_IDENTITY_PATTERN,
    evaluate_rules,
    extract_auth_failure_identity,
)
from remediation.orchestrator import is_remediation_successful
from remediation.remediation import RemediationResult
from reporter.slack_notifier import build_slack_payload, build_waf_slack_payload

MOCK_DATA_DIR = Path(__file__).parent / "mock_data"


def test_incident_report_from_mock_json() -> None:
    """mock_incident.json 파일이 IncidentReport 계약을 완벽히 만족하는지 검증."""
    mock_file = MOCK_DATA_DIR / "mock_incident.json"
    assert mock_file.exists(), "mock_incident.json 파일이 누락되었습니다."

    data = json.loads(mock_file.read_text(encoding="utf-8"))
    report = IncidentReport.model_validate(data)

    assert report.incident_id == "INC-20260904-001"
    assert report.attack_type == "SSH Brute Force"
    assert report.mitre_id == "T1110.001"
    assert report.risk_level == "HIGH"
    assert report.source_ip == "198.51.100.50"
    assert report.target_identifier == "i-0abcd1234ef567890"
    assert "admin" in report.target_accounts
    assert isinstance(report.target_accounts, tuple)
    assert isinstance(report.recommendations, tuple)
    assert report.action_required == "BLOCK_AND_QUARANTINE"
    assert len(report.recommendations) >= 1


@pytest.mark.parametrize(
    "invalid_ip",
    [
        "999.999.999.999",
        "198.51.100.50/24",
        "198.51.100",
        "256.0.0.1",
        "not-an-ip",
    ],
)
def test_incident_report_invalid_ip_rejected(invalid_ip: str) -> None:
    """비정상 IPv4 입력 시 Pydantic ValidationError 발생 검증."""
    valid_data = {
        "incident_id": "INC-20260904-001",
        "attack_type": "SSH Brute Force",
        "mitre_id": "T1110.001",
        "risk_level": "HIGH",
        "source_ip": invalid_ip,
        "target_identifier": "i-0abcd1234ef567890",
        "target_accounts": ["admin"],
        "summary_ko": "요약 테스트",
        "action_required": "QUARANTINE_EC2",
        "recommendations": ["조치 권고"],
    }
    with pytest.raises(ValidationError):
        IncidentReport.model_validate(valid_data)


@pytest.mark.parametrize(
    "invalid_instance_id",
    [
        "vol-0abcd1234ef567890",
        "i-1234",
        "i-0abcd1234ef567890zz",
        "server-01",
    ],
)
def test_incident_report_invalid_instance_id_rejected(invalid_instance_id: str) -> None:
    """AWS EC2 규격에 맞지 않는 target_identifier 입력 시 ValidationError 발생 검증."""
    valid_data = {
        "incident_id": "INC-20260904-001",
        "attack_type": "SSH Brute Force",
        "mitre_id": "T1110.001",
        "risk_level": "HIGH",
        "source_ip": "198.51.100.50",
        "target_identifier": invalid_instance_id,
        "target_accounts": ["admin"],
        "summary_ko": "요약 테스트",
        "action_required": "QUARANTINE_EC2",
        "recommendations": ["조치 권고"],
    }
    with pytest.raises(ValidationError):
        IncidentReport.model_validate(valid_data)


def test_syslog_auth_log_parsing() -> None:
    """mock_auth.log 파일의 모든 라인이 표준 규격대로 정확히 파싱되는지 검증."""
    log_file = MOCK_DATA_DIR / "mock_auth.log"
    assert log_file.exists(), "mock_auth.log 파일이 누락되었습니다."

    raw_text = log_file.read_text(encoding="utf-8")
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    assert len(lines) == 5

    parsed_events = [SyslogAuthEvent.parse_line(line) for line in lines]
    assert all(e is not None for e in parsed_events)

    # 1번째 라인 검증: invalid user admin
    e0 = parsed_events[0]
    assert e0 is not None
    assert e0.is_invalid_user is True
    assert e0.username == "admin"
    assert e0.source_ip == "198.51.100.50"
    assert e0.port == 49152

    # 3번째 라인 검증: root (일반 실패)
    e2 = parsed_events[2]
    assert e2 is not None
    assert e2.is_invalid_user is False
    assert e2.username == "root"
    assert e2.source_ip == "198.51.100.50"
    assert e2.port == 49154


def test_syslog_auth_log_parsing_iso8601() -> None:
    """Ubuntu 22.04/24.04 최신 ISO 8601 타임스탬프 로그 파싱 검증."""
    iso_line = (
        "2026-09-04T14:20:01.123456+00:00 target-ec2 sshd[12341]: "
        "Failed password for invalid user admin from 198.51.100.50 port 49152 ssh2"
    )
    event = SyslogAuthEvent.parse_line(iso_line)
    assert event is not None
    assert event.timestamp_str == "2026-09-04T14:20:01.123456+00:00"
    assert event.hostname == "target-ec2"
    assert event.username == "admin"
    assert event.is_invalid_user is True
    assert event.source_ip == "198.51.100.50"
    assert event.port == 49152


def test_cw_event_from_mock_json_and_roundtrip() -> None:
    """mock_cw_event.json의 Lambda 페이로드 디코딩 및 왕복(Roundtrip) 무결성 검증."""
    cw_file = MOCK_DATA_DIR / "mock_cw_event.json"
    assert cw_file.exists(), "mock_cw_event.json 파일이 누락되었습니다."

    event_data = json.loads(cw_file.read_text(encoding="utf-8"))
    assert "awslogs" in event_data
    assert "data" in event_data["awslogs"]

    payload = CloudWatchLogsPayload.from_awslogs_data(event_data["awslogs"]["data"])
    assert payload.messageType == "DATA_MESSAGE"
    assert payload.owner == "123456789012"
    assert payload.logGroup == "/cloudshield/target/auth-log"
    assert payload.logStream == "i-0abcd1234ef567890"
    assert "CloudShield-FailedPassword-Filter" in payload.subscriptionFilters
    assert len(payload.logEvents) == 5
    for evt in payload.logEvents:
        assert "198.51.100.50" in evt.message

    # 왕복 인코딩/디코딩 검증
    encoded = payload.to_awslogs_data()
    restored = CloudWatchLogsPayload.from_awslogs_data(encoded)
    assert restored == payload


def test_contract_schema_immutability() -> None:
    """공통 인터페이스 계약 모델의 필드 목록 불변성(Contract Drift Guard) 검증.

    Why:
        비전공자 팀원이나 에이전트의 작업 중 계약 필드가 누락되거나 변경되는 사고를 사전 방지함.
    """
    expected_incident_fields = {
        "incident_id",
        "attack_type",
        "mitre_id",
        "risk_level",
        "source_ip",
        "target_identifier",
        "target_accounts",
        "summary_ko",
        "action_required",
        "recommendations",
    }
    actual_incident_fields = set(IncidentReport.model_fields.keys())
    assert actual_incident_fields == expected_incident_fields, (
        f"IncidentReport 스키마가 변조되었습니다! 누락/추가 필드: "
        f"{actual_incident_fields ^ expected_incident_fields}"
    )

    expected_cw_fields = {
        "messageType",
        "owner",
        "logGroup",
        "logStream",
        "subscriptionFilters",
        "logEvents",
    }
    actual_cw_fields = set(CloudWatchLogsPayload.model_fields.keys())
    assert actual_cw_fields == expected_cw_fields, (
        f"CloudWatchLogsPayload 스키마가 변조되었습니다! 누락/추가 필드: "
        f"{actual_cw_fields ^ expected_cw_fields}"
    )

    expected_nginx_fields = {
        "source_ip",
        "timestamp_str",
        "method",
        "uri",
        "status_code",
        "response_time",
        "user_agent",
        "raw_message",
    }
    actual_nginx_fields = set(NginxAccessLogEvent.model_fields.keys())
    assert actual_nginx_fields == expected_nginx_fields, (
        f"NginxAccessLogEvent 스키마가 변조되었습니다! 누락/추가 필드: "
        f"{actual_nginx_fields ^ expected_nginx_fields}"
    )


@pytest.mark.parametrize(
    ("filename", "expected_action", "expected_risk"),
    [
        ("mock_incident_spray.json", "BLOCK_AND_QUARANTINE", "HIGH"),
        ("mock_incident_waf_only.json", "BLOCK_WAF", "MEDIUM"),
        ("mock_incident_alert_only.json", "ALERT_ONLY", "LOW"),
    ],
)
def test_extended_incident_reports_from_mock_json(
    filename: str, expected_action: str, expected_risk: str
) -> None:
    """확장 침해사고 모의 데이터가 IncidentReport 계약을 완벽히 만족하는지 검증."""
    mock_file = MOCK_DATA_DIR / filename
    assert mock_file.exists(), f"{filename} 파일이 누락되었습니다."

    data = json.loads(mock_file.read_text(encoding="utf-8"))
    report = IncidentReport.model_validate(data)

    assert report.action_required == expected_action
    assert report.risk_level == expected_risk
    assert len(report.recommendations) >= 1 or expected_action == "NONE"


def test_cw_batch_event_decoding_and_roundtrip() -> None:
    """다건 배치 mock_cw_batch_event.json의 디코딩 및 왕복 압축 무결성 검증."""
    cw_file = MOCK_DATA_DIR / "mock_cw_batch_event.json"
    assert cw_file.exists(), "mock_cw_batch_event.json 파일이 누락되었습니다."

    event_data = json.loads(cw_file.read_text(encoding="utf-8"))
    payload = CloudWatchLogsPayload.from_awslogs_data(event_data["awslogs"]["data"])

    assert payload.messageType == "DATA_MESSAGE"
    assert len(payload.logEvents) == 5
    assert payload.logStream == "i-0abcd1234ef567890"

    # 왕복 인코딩/디코딩 무결성 검증
    encoded = payload.to_awslogs_data()
    restored = CloudWatchLogsPayload.from_awslogs_data(encoded)
    assert restored == payload


def test_noisy_auth_log_parsing() -> None:
    """mock_auth_noisy.log에서 SSH 실패 로그만 정확히 필터링 파싱되는지 검증."""
    log_file = MOCK_DATA_DIR / "mock_auth_noisy.log"
    assert log_file.exists(), "mock_auth_noisy.log 파일이 누락되었습니다."

    raw_text = log_file.read_text(encoding="utf-8")
    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    assert len(lines) == 13

    parsed_events = [SyslogAuthEvent.parse_line(line) for line in lines]
    valid_events = [e for e in parsed_events if e is not None]

    # 13개 중 실패 이벤트(Sep 04 5건 + 198.51.100.99 1건) 총 6건만 파싱되어야 함
    assert len(valid_events) == 6
    assert all(e.process == "sshd" for e in valid_events)


def test_nginx_access_log_parsing() -> None:
    """Nginx Combined 및 cloudshield_combined 로그 라인 파싱 정합성 검증."""
    # 1. cloudshield_combined 포맷 (response_time 포함)
    line_full = (
        "198.51.100.77 - - [28/Sep/2026:11:52:38 +0000] "
        '"GET /admin HTTP/1.1" 401 150 "-" "curl/7.81.0" 0.002 "-"'
    )
    event_full = NginxAccessLogEvent.parse_line(line_full)
    assert event_full is not None
    assert event_full.source_ip == "198.51.100.77"
    assert event_full.timestamp_str == "28/Sep/2026:11:52:38 +0000"
    assert event_full.method == "GET"
    assert event_full.uri == "/admin"
    assert event_full.status_code == 401
    assert event_full.response_time == 0.002
    assert event_full.user_agent == "curl/7.81.0"
    assert event_full.raw_message == line_full

    # 2. 표준 Combined 포맷 (response_time 미포함 시 기본값 0.0)
    line_std = (
        "203.0.113.10 - admin [28/Sep/2026:12:00:01 +0000] "
        '"POST /api/v1/login HTTP/1.1" 200 45 "https://example.com" "Mozilla/5.0"'
    )
    event_std = NginxAccessLogEvent.parse_line(line_std)
    assert event_std is not None
    assert event_std.source_ip == "203.0.113.10"
    assert event_std.timestamp_str == "28/Sep/2026:12:00:01 +0000"
    assert event_std.method == "POST"
    assert event_std.uri == "/api/v1/login"
    assert event_std.status_code == 200
    assert event_std.response_time == 0.0
    assert event_std.user_agent == "Mozilla/5.0"


def test_nginx_access_log_url_unquote() -> None:
    """Nginx access.log 파싱 시 1차 URL unquote 및 에러 복원력 검증.

    Why:
        공격자가 WAF나 시그니처 매칭을 우회하기 위해 URL 인코딩을 적용하더라도
        계약 모델 단계에서 1차 unquote를 수행하여 동일한 탐지 인터페이스를 제공함.
    """
    # 1. 단일 URL 인코딩 파싱 검증
    encoded_line = (
        "198.51.100.77 - - [28/Sep/2026:11:52:38 +0000] "
        '"GET /admin%20login%2Ftest%3Fkey%3Dval HTTP/1.1" 401 150 "-" "curl/7.81.0" 0.002 "-"'
    )
    event = NginxAccessLogEvent.parse_line(encoded_line)
    assert event is not None
    assert event.uri == "/admin login/test?key=val"

    # 2. 비정상 퍼센트 인코딩(%ZZ) 및 디코딩 불가 시그니처 인입 시에도 에러 없이 안전 유지
    malformed_line = (
        "198.51.100.77 - - [28/Sep/2026:11:52:38 +0000] "
        '"GET /test%ZZ%E0%A4 HTTP/1.1" 404 150 "-" "curl/7.81.0" 0.001 "-"'
    )
    malformed_event = NginxAccessLogEvent.parse_line(malformed_line)
    assert malformed_event is not None
    assert "%ZZ" in malformed_event.uri


def test_nginx_access_log_immutability() -> None:
    """NginxAccessLogEvent 모델의 불변성(frozen=True) 및 임의 필드 금지(extra=forbid) 검증."""
    line = (
        "198.51.100.77 - - [28/Sep/2026:11:52:38 +0000] "
        '"GET /admin HTTP/1.1" 401 150 "-" "curl/7.81.0" 0.002 "-"'
    )
    event = NginxAccessLogEvent.parse_line(line)
    assert event is not None

    # frozen=True 속성 변경 시도 차단
    with pytest.raises(ValidationError):
        event.status_code = 200  # type: ignore[misc]

    # extra='forbid' 정의되지 않은 필드 인입 차단
    with pytest.raises(ValidationError):
        NginxAccessLogEvent(
            source_ip="198.51.100.77",
            timestamp_str="28/Sep/2026:11:52:38 +0000",
            method="GET",
            uri="/admin",
            status_code=401,
            response_time=0.002,
            user_agent="curl/7.81.0",
            raw_message=line,
            extra_field="disallowed",  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    "invalid_line",
    [
        "",
        "   ",
        (
            "Sep 03 14:20:01 target-ec2 sshd[12341]: "
            "Failed password for invalid user admin from 198.51.100.50 port 49152 ssh2"
        ),
        "invalid non-log string",
        "-",
    ],
)
def test_nginx_access_log_invalid_lines_return_none(invalid_line: str) -> None:
    """Nginx access.log 규격에 맞지 않는 라인 인입 시 None 안전 반환 검증."""
    assert NginxAccessLogEvent.parse_line(invalid_line) is None


# ===========================================================================
# 직무 간 교차 인터페이스 계약 하드가드 (Cross-Domain Consistency Guards)
# 소유자: 클라우드 A (테크 리드 전담 플랫폼 거버넌스)
# ===========================================================================


def test_cross_domain_rules_and_mapper_consistency() -> None:
    """[보안 ↔ 매퍼 교차 하드가드] rules.py와 incident_mapper.py 간의 룰명 및 액션 정합성 검증.

    Why:
        보안 시그니처 룰 엔진이 탐지한 룰명(rule_name)이 침해사고 매퍼의 메타데이터 정의와
        1:1 일치하지 않으면 IncidentReport 승격 단계에서 ValueError 또는 KeyError가 발생하여
        전체 대응 파이프라인이 중단되는 결함을 사전에 방지함.

    Constraints:
        - _RULE_METADATA의 모든 키는 rules.py에서 탐지 가능한 유효 룰이어야 함.
        - 메타데이터에 정의된 action_required는 IncidentReport의 유효 액션이어야 함.
        - risk_level은 HIGH, MEDIUM, LOW 중 하나여야 함.
    """
    valid_actions = {
        "BLOCK_WAF",
        "QUARANTINE_EC2",
        "REVOKE_IAM_SESSION",
        "BLOCK_AND_QUARANTINE",
        "BLOCK_IP_ONLY",
        "ALERT_ONLY",
        "NONE",
    }
    valid_risks = {"HIGH", "MEDIUM", "LOW"}

    # 최소 필수 룰 키 검증
    expected_core_rules = {"SSH_BRUTE_FORCE", "SSH_PASSWORD_SPRAYING"}
    actual_rules = set(_RULE_METADATA.keys())
    assert expected_core_rules.issubset(actual_rules), (
        "incident_mapper._RULE_METADATA에 필수 룰이 누락되었습니다: "
        f"{expected_core_rules - actual_rules}"
    )

    for rule_name, meta in _RULE_METADATA.items():
        assert meta["action_required"] in valid_actions, (
            f"룰 {rule_name}의 action_required({meta['action_required']})가 "
            f"IncidentReport 계약 모델에 정의되지 않았습니다."
        )
        assert meta["risk_level"] in valid_risks, (
            f"룰 {rule_name}의 risk_level({meta['risk_level']})이 유효하지 않습니다."
        )

        # map_threat_to_incident를 통한 IncidentReport 생성 무결성 검증
        report = map_threat_to_incident(
            is_threat=True,
            rule_name=rule_name,
            source_ip="198.51.100.50",
            target_accounts=("admin", "root"),
            incident_id=f"INC-TEST-{rule_name}",
        )
        assert isinstance(report, IncidentReport)
        assert report.action_required == meta["action_required"]
        assert report.risk_level == meta["risk_level"]


@pytest.mark.parametrize(
    "action_required",
    [
        "BLOCK_WAF",
        "QUARANTINE_EC2",
        "REVOKE_IAM_SESSION",
        "BLOCK_AND_QUARANTINE",
        "BLOCK_IP_ONLY",
        "ALERT_ONLY",
        "NONE",
    ],
)
def test_cross_domain_all_action_types_slack_rendering(action_required: str) -> None:
    """[클라우드 B 교차 하드가드] IncidentReport 전 action_required Slack 카드 렌더링 검증.

    Why:
        새로운 대응 액션이 IncidentReport 스키마에 추가되었을 때, 클라우드 B의
        Slack 블록 킷 빌더가 이를 처리하지 못해 발생하는 런타임 예외 및 관제 누락을 원천 방지함.

    Constraints:
        - 7대 대응 액션 전체에 대해 build_slack_payload 및 build_waf_slack_payload가 성공해야 함.
        - 반환된 페이로드는 4대 필수 키를 포함해야 함:
          (incident_id, rule_name, source_ip, remediation_action).
        - JSON 직렬화(json.dumps)가 에러 없이 완료되어야 함.
    """
    report = IncidentReport(
        incident_id="INC-20260930-TEST",
        attack_type="SSH Brute Force",
        mitre_id="T1110.001",
        risk_level="HIGH",
        source_ip="198.51.100.50",
        target_identifier="i-0abcd1234ef567890",
        target_accounts=("admin",),
        summary_ko="교차 하드가드 렌더링 테스트",
        action_required=action_required,
        recommendations=("테스트 권고 조치",),
    )

    dummy_remediation: RemediationResult = {
        "waf_blocked": True,
        "quarantine_applied": True,
        "iam_revoked": False,
    }

    # 1. 표준 Slack Block Kit 페이로드 렌더링 검증
    payload = build_slack_payload(report, remediation_result=dummy_remediation)
    assert payload["incident_id"] == "INC-20260930-TEST"
    assert payload["rule_name"] == "SSH Brute Force"
    assert payload["source_ip"] == "198.51.100.50"
    assert payload["remediation_action"] == action_required
    assert "blocks" in payload
    # JSON 직렬화 안전성 검증
    json_str = json.dumps(payload, ensure_ascii=False)
    assert len(json_str) > 0

    # 2. WAF 전용 Slack Block Kit 페이로드 렌더링 검증
    waf_payload = build_waf_slack_payload(report, remediation_result=dummy_remediation)
    assert waf_payload["incident_id"] == "INC-20260930-TEST"
    assert waf_payload["remediation_action"] == action_required
    assert "blocks" in waf_payload
    waf_json_str = json.dumps(waf_payload, ensure_ascii=False)
    assert len(waf_json_str) > 0


def test_cross_domain_network_mock_auth_matches_security_regex() -> None:
    """[네트워크 ↔ 보안 교차 하드가드] mock_auth.log 공격 로그의 보안 정규식 100% 매칭 검증.

    Why:
        네트워크 담당이 수집한 모의 공격 로그 원문이 보안 담당의 정규식 시그니처 패턴에
        부합하지 않아 실제 침해 탐지가 실패하는 '모의 훈련과 탐지 룰 간의 괴리'를 방지함.

    Constraints:
        - mock_auth.log의 5개 모든 실패 라인이 AUTH_FAILURE_IDENTITY_PATTERN에 100% 매칭되어야 함.
        - 추출된 source_ip는 '198.51.100.50'이어야 함.
        - 추출된 username은 'admin', 'root', 'guest' 중 하나여야 함.
    """
    log_file = MOCK_DATA_DIR / "mock_auth.log"
    assert log_file.exists(), "mock_auth.log 파일이 누락되었습니다."

    lines = [
        line.strip() for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert len(lines) == 5, f"mock_auth.log 라인 수가 5건이 아닙니다: {len(lines)}"

    expected_accounts = {"admin", "root", "guest"}
    extracted_accounts = set()

    for line in lines:
        match = AUTH_FAILURE_IDENTITY_PATTERN.search(line)
        assert match is not None, f"로그 라인이 보안 정규식에 매칭되지 않음: {line}"

        identity = extract_auth_failure_identity(line)
        assert identity is not None
        source_ip, username = identity
        assert source_ip == "198.51.100.50"
        assert username in expected_accounts
        extracted_accounts.add(username)

    assert extracted_accounts == expected_accounts, (
        f"추출된 계정 목록({extracted_accounts})이 "
        f"기대 계정({expected_accounts})과 일치하지 않습니다."
    )


def test_cross_domain_e2e_data_chain_consistency() -> None:
    """[전 직무 관통 E2E 하드가드] mock_auth -> mock_cw -> rules -> mapper -> remediation -> slack.

    Why:
        수집(CW Logs) -> 탐지(rules) -> 분석(mapper) -> 차단(remediation) -> 전파(slack)로 이어지는
        10초 자동 관통 데모 파이프라인의 데이터 체인이 단절 없이
        인과적으로 연결됨을 단일 하드가드로 증명함.
    """
    # 1. mock_auth.log 읽기
    auth_log_file = MOCK_DATA_DIR / "mock_auth.log"
    raw_lines = [
        line.strip()
        for line in auth_log_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(raw_lines) == 5

    # 2. mock_cw_event.json 디코딩 및 메시지 1:1 정합성 검증
    cw_event_file = MOCK_DATA_DIR / "mock_cw_event.json"
    cw_data = json.loads(cw_event_file.read_text(encoding="utf-8"))
    payload = CloudWatchLogsPayload.from_awslogs_data(cw_data["awslogs"]["data"])
    assert len(payload.logEvents) == 5
    for idx, evt in enumerate(payload.logEvents):
        assert evt.message == raw_lines[idx], (
            f"CW Event 메시지가 mock_auth.log 원문과 일치하지 않음 (인덱스 {idx}): "
            f"'{evt.message}' vs '{raw_lines[idx]}'"
        )

    # 3. SyslogAuthEvent 파싱 및 보안 룰 평가
    parsed_events = [SyslogAuthEvent.parse_line(evt.message) for evt in payload.logEvents]
    valid_events = [e for e in parsed_events if e is not None]
    assert len(valid_events) == 5

    is_threat, rule_name = evaluate_rules(valid_events)
    assert is_threat is True
    # 5건 중 admin 2건, root 2건, guest 1건 -> 고유 계정 3개 시도로 SSH_PASSWORD_SPRAYING 탐지
    assert rule_name == "SSH_PASSWORD_SPRAYING"

    # 4. incident_mapper를 통한 IncidentReport 승격
    unique_accounts = tuple(dict.fromkeys(e.username for e in valid_events))
    report = map_threat_to_incident(
        is_threat=is_threat,
        rule_name=rule_name,
        source_ip=valid_events[0].source_ip,
        target_accounts=unique_accounts,
        target_identifier=payload.logStream,
    )
    assert report.source_ip == "198.51.100.50"
    assert report.target_accounts == ("admin", "root", "guest")
    assert report.target_identifier == "i-0abcd1234ef567890"

    # 5. remediation 및 orchestrator 판정 무결성
    dummy_result: RemediationResult = {
        "waf_blocked": True,
        "quarantine_applied": False,
        "iam_revoked": False,
    }
    assert isinstance(is_remediation_successful(report.action_required, dummy_result), bool)

    # 6. Slack 전파 카드 빌드 무결성
    slack_card = build_slack_payload(report, remediation_result=dummy_result)
    assert slack_card["incident_id"] == report.incident_id
    assert slack_card["source_ip"] == "198.51.100.50"


def test_cross_domain_orchestrator_action_exhaustiveness() -> None:
    """[플랫폼 하드가드] is_remediation_successful의 모든 action_required 결정론적 판정 검증.

    Why:
        대응 액션 분기 로직에서 알 수 없는 액션으로 인한 침묵하는 실패(Silent Failure)나
        런타임 크래시를 방지하고, 모든 액션에 대해 명시적 True/False를 반환하도록 강제함.
    """
    valid_actions = [
        "BLOCK_WAF",
        "QUARANTINE_EC2",
        "REVOKE_IAM_SESSION",
        "BLOCK_AND_QUARANTINE",
        "BLOCK_IP_ONLY",
        "ALERT_ONLY",
        "NONE",
    ]

    all_true_result: RemediationResult = {
        "waf_blocked": True,
        "quarantine_applied": True,
        "iam_revoked": True,
    }
    all_false_result: RemediationResult = {
        "waf_blocked": False,
        "quarantine_applied": False,
        "iam_revoked": False,
    }

    for action in valid_actions:
        res_true = is_remediation_successful(action, all_true_result)
        res_false = is_remediation_successful(action, all_false_result)
        assert isinstance(res_true, bool)
        assert isinstance(res_false, bool)
        # 모든 차단이 실패한 상태에서는 어떤 액션도 성공(True)으로 판정될 수 없음
        assert res_false is False
