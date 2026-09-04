# CloudShield 인터페이스 계약 검증 테스트
# 소유자: 클라우드 A
"""Pydantic V2 데이터 계약 모델 및 Mock 데이터 정합성 검증 테스트."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.events import CloudWatchLogsPayload, SyslogAuthEvent
from contracts.incident import IncidentReport

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
    assert len(payload.logEvents) == 1
    assert "198.51.100.50" in payload.logEvents[0].message

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
