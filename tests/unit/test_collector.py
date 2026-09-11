# CloudShield 단위 테스트: CloudWatch Logs 프로세서
# 소유자: 클라우드 B 담당
"""CloudWatch Logs 압축 해제기(cw_processor.py) 단위 테스트."""

from __future__ import annotations

from typing import Any

import pytest

from collector.cw_processor import decode_cw_logs


def test_decode_cw_logs_interface(sample_cw_event: dict[str, Any]) -> None:
    """decode_cw_logs 함수 시그니처 및 스켈레톤 인터페이스 스모크 검증.

    Why:
        클라우드 B 담당 에이전트가 cw_processor.py 구현 착수 전 모듈 import 경로와
        함수 시그니처(Lambda 이벤트 딕셔너리 수락 여부)를 즉각 검증함.
    """
    with pytest.raises(NotImplementedError, match="클라우드 B 담당자 구현 영역"):
        decode_cw_logs(sample_cw_event)


@pytest.mark.skip(reason="클라우드 B 구현 대기")
def test_decode_cw_logs_success(sample_cw_event: dict[str, Any]) -> None:
    """CloudWatch Logs 페이로드 Gzip 압축 해제 및 로그 문자열 추출 검증."""
    lines = decode_cw_logs(sample_cw_event)
    assert isinstance(lines, list)
    assert len(lines) >= 1
    assert "Failed password" in lines[0]


def test_amazon_cloudwatch_agent_config_validity() -> None:
    """amazon-cloudwatch-agent.json 설정 파일의 정적 JSON 유효성 및 필수 키 검증.

    Why:
        클라우드 B 담당자가 정의한 CloudWatch Agent 수집 명세가 JSON 스키마를 만족하고
        타깃 로그 경로(/var/log/auth.log) 및 CloudWatch Logs 그룹명(/cloudshield/target/auth-log)을
        정확히 지정하고 있는지 자동 검증함.
    """
    import json
    from pathlib import Path

    config_path = Path("src/collector/amazon-cloudwatch-agent.json")
    assert config_path.exists(), (
        "src/collector/amazon-cloudwatch-agent.json 파일이 존재해야 합니다."
    )

    with config_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    collect_list = (
        data.get("logs", {}).get("logs_collected", {}).get("files", {}).get("collect_list", [])
    )
    assert len(collect_list) >= 1, "collect_list 항목이 1개 이상 존재해야 합니다."

    auth_log_config = collect_list[0]
    assert auth_log_config["file_path"] == "/var/log/auth.log"
    assert auth_log_config["log_group_name"] == "/cloudshield/target/auth-log"
    assert auth_log_config["log_stream_name"] == "{instance_id}"
    assert auth_log_config["timestamp_format"] == "%Y-%m-%dT%H:%M:%S.%f%z"

    # 루트와 src/collector/ 의 사본 동기화 검증
    root_config_path = Path("amazon-cloudwatch-agent.json")
    assert root_config_path.exists(), "루트 amazon-cloudwatch-agent.json 파일이 존재해야 합니다."
    with root_config_path.open("r", encoding="utf-8") as f_root:
        root_data = json.load(f_root)
    assert root_data == data, "루트 설정과 src/collector/ 설정 내용이 일치해야 합니다."


def test_collector_log_timestamp_format_parsing() -> None:
    """대표 로그(mock_auth.log 및 mock_auth_noisy.log)의 타임스탬프 정합성 및 수집 포맷 검증.

    Why:
        CloudWatch Agent의 timestamp_format (%Y-%m-%dT%H:%M:%S.%f%z)과 타깃 인스턴스/mock 로그의
        ISO 8601 및 BSD 타임스탬프 정합성을 검증하여 이벤트 발생 시각 미추출 및
        대응 지연 수치 왜곡을 방지함.
    """
    from datetime import datetime
    from pathlib import Path

    from contracts.events import SyslogAuthEvent

    mock_dir = Path("tests/mock_data")
    auth_log = mock_dir / "mock_auth.log"
    auth_noisy_log = mock_dir / "mock_auth_noisy.log"

    assert auth_log.exists() and auth_noisy_log.exists()

    # 1. ISO 8601 포맷 타임스탬프 파싱 검증 (%Y-%m-%dT%H:%M:%S.%f%z)
    iso_line = (
        "2026-09-04T15:00:01.102345+00:00 target-ec2 sshd[21001]: "
        "Accepted publickey for ubuntu from 192.0.2.10 port 52140 ssh2"
    )
    iso_timestamp_str = iso_line.split()[0]
    parsed_dt = datetime.fromisoformat(iso_timestamp_str)
    assert parsed_dt.year == 2026 and parsed_dt.month == 9 and parsed_dt.day == 4

    # 2. BSD Syslog 포맷 타임스탬프 파싱 검증 (%b %d %H:%M:%S)
    bsd_line = (
        "Sep 03 14:20:01 target-ec2 sshd[12341]: "
        "Failed password for invalid user admin from 198.51.100.50 port 49152 ssh2"
    )
    event_bsd = SyslogAuthEvent.parse_line(bsd_line)
    assert event_bsd is not None
    assert event_bsd.timestamp_str == "Sep 03 14:20:01"
    parsed_bsd_dt = datetime.strptime(f"2026 {event_bsd.timestamp_str}", "%Y %b %d %H:%M:%S")
    assert parsed_bsd_dt.month == 9 and parsed_bsd_dt.day == 3

    # 3. mock_auth_noisy.log 내 ISO 8601 및 BSD 혼재 로그 정합성 검증
    with auth_noisy_log.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    parsed_events = [
        SyslogAuthEvent.parse_line(line) for line in lines if "Failed password" in line
    ]
    assert len(parsed_events) >= 5, (
        "mock_auth_noisy.log 내 실패 로그 이벤트가 정상 추출되어야 합니다."
    )
    for ev in parsed_events:
        assert ev is not None
        assert ev.source_ip != ""
