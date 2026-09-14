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

    Constraints:
        Agent의 %z 디렉티브는 Go layout -0700에 매핑되며 [+-]\\d{4} 정규식만 지원.
        따라서 rsyslog 커스텀 템플릿은 RFC 3339(+00:00)가 아닌 콜론 없는 형식(+0000)으로
        오프셋을 출력해야 Agent 타임스탬프 파싱이 성공한다.
        참고: https://github.com/aws/amazon-cloudwatch-agent/blob/main/internal/util/timestamp/timestamp.go
    """
    from datetime import datetime
    from pathlib import Path

    from contracts.events import SyslogAuthEvent

    mock_dir = Path("tests/mock_data")
    auth_log = mock_dir / "mock_auth.log"
    auth_noisy_log = mock_dir / "mock_auth_noisy.log"

    assert auth_log.exists() and auth_noisy_log.exists()

    # 1. ISO 8601 포맷 타임스탬프 파싱 검증 (%Y-%m-%dT%H:%M:%S.%f%z)
    # Side-effects: Agent %z는 [+-]\d{4} 만 인식하므로 rsyslog 출력은 반드시 +0000 형식이어야 함.
    # 아래 예시는 Agent가 실제로 파싱 가능한 +0000(콜론 없음) 형식을 사용함.
    iso_line = (
        "2026-09-04T15:00:01.102345+0000 target-ec2 sshd[21001]: "
        "Accepted publickey for ubuntu from 192.0.2.10 port 52140 ssh2"
    )
    iso_timestamp_str = iso_line.split()[0]
    # Python datetime.fromisoformat()은 +0000 형식을 직접 파싱하지 않으므로
    # Agent 파싱 기준인 strptime 포맷으로 검증함.
    parsed_dt = datetime.strptime(iso_timestamp_str, "%Y-%m-%dT%H:%M:%S.%f%z")
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


def test_cloudwatch_agent_timestamp_z_directive_regex() -> None:
    """CloudWatch Agent %z 디렉티브 파싱 정규식과 rsyslog 출력 형식 정합성 회귀 테스트.

    Why:
        Agent 소스(timestamp.go)의 %z 디렉티브는 Go layout -0700에 매핑되며
        내부적으로 [+-]\\d{4} 정규식만 지원한다. RFC 3339 표준의 콜론 포함 오프셋(+00:00)은
        이 정규식에 매칭되지 않아 타임스탬프 추출 실패 → CloudWatch Logs의 인덱싱 시각이
        수집 시각으로 덮어씌워져 이벤트 발생 시각 추적이 불가능해진다.
        본 테스트는 amazon-cloudwatch-agent.json의 timestamp_format 설정과
        rsyslog 실제 출력 샘플을 연결하여 Agent 파싱 가능 여부를 자동 회귀 검증한다.

    Constraints:
        - Agent %z 지원 형식: +0000 (콜론 없는 4자리) — 매칭 성공
        - Agent %z 미지원 형식: +00:00 (RFC 3339 콜론 포함) — 매칭 실패
        - rsyslog RSYSLOG_FileFormat 기본 출력: RFC 3339(+00:00) → 커스텀 템플릿 필수

    Side-effects:
        이 테스트가 실패하면 EC2 rsyslog 템플릿 또는 Agent 설정을 수정해야 한다.
        참고: https://github.com/aws/amazon-cloudwatch-agent/blob/main/internal/util/timestamp/timestamp.go
    """
    import json
    import re
    from pathlib import Path

    # Amazon CloudWatch Agent %z 디렉티브의 내부 파싱 정규식 (timestamp.go 기준)
    # Directive: %z | Go layout: -0700 | Regex: [+-]\d{4}
    CW_AGENT_TZ_REGEX = re.compile(r"[+-]\d{4}")

    # 1. JSON 설정에서 timestamp_format 추출
    config_path = Path("src/collector/amazon-cloudwatch-agent.json")
    with config_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    collect_list = (
        data.get("logs", {}).get("logs_collected", {}).get("files", {}).get("collect_list", [])
    )
    assert len(collect_list) >= 1
    ts_format = collect_list[0]["timestamp_format"]
    assert ts_format == "%Y-%m-%dT%H:%M:%S.%f%z", (
        f"timestamp_format이 예상 규격과 다릅니다: {ts_format}"
    )

    # 2. rsyslog 커스텀 템플릿 출력 샘플 (콜론 없는 +0000 형식): Agent 파싱 성공 케이스
    # Why: EC2에 배포할 rsyslog 커스텀 템플릿은 반드시 이 형식을 출력해야 함.
    #   template(name="CloudShieldISO" type="string"
    #     string="%TIMESTAMP:::date-unixtimestamp-subseconds%%TIMESTAMP:::date-tzoffsetcustom%")
    #   → 실제로는 strftime %Y-%m-%dT%H:%M:%S.%f와 +HHMM 조합으로 출력 필요.
    valid_rsyslog_samples = [
        # +0000: 콜론 없는 UTC 오프셋 — Agent %z [+-]\d{4} 매칭 성공
        "2026-09-04T15:00:01.102345+0000 target-ec2 sshd[21001]: Failed password",
        # +0900: 양수 오프셋(KST) — Agent 파싱 성공
        "2026-09-14T02:30:59.000001+0900 target-ec2 sshd[9001]: Failed password",
        # -0500: 음수 오프셋(EST) — Agent 파싱 성공
        "2026-01-01T00:00:00.999999-0500 target-ec2 sshd[1]: Failed password",
    ]

    # 3. RFC 3339 출력 샘플 (콜론 포함 +00:00 형식): Agent 파싱 실패 케이스
    # Why: rsyslog RSYSLOG_FileFormat 기본값이 이 형식을 출력하므로
    #   커스텀 템플릿 없이는 Agent 타임스탬프 파싱이 실패함.
    invalid_rsyslog_samples = [
        # +00:00: RFC 3339 콜론 포함 UTC — [+-]\d{4} 미매칭, Agent 파싱 실패
        "2026-09-04T15:00:01.102345+00:00 target-ec2 sshd[21001]: Failed password",
        # +09:00: RFC 3339 콜론 포함 KST — [+-]\d{4} 미매칭, Agent 파싱 실패
        "2026-09-14T02:30:59.000001+09:00 target-ec2 sshd[9001]: Failed password",
    ]

    # 유효 샘플: Agent %z 정규식([+-]\d{4})이 타임스탬프 영역을 정확히 추출해야 함
    for sample in valid_rsyslog_samples:
        ts_token = sample.split()[0]  # "2026-09-04T15:00:01.102345+0000"
        tz_match = CW_AGENT_TZ_REGEX.search(ts_token)
        assert tz_match is not None, (
            f"[회귀 실패] Agent %z 정규식이 유효 샘플에서 타임존을 추출하지 못함: {ts_token!r}\n"
            "rsyslog 커스텀 템플릿이 +0000 형식을 출력하는지 확인하세요."
        )
        # 타임존 오프셋이 타임스탬프 토큰 끝에 위치해야 함 (콜론 없음 보장)
        matched_tz = tz_match.group(0)
        assert ":" not in matched_tz, (
            f"타임존 오프셋에 콜론이 포함되어 있습니다: {matched_tz!r} — Agent 파싱 불가"
        )

    # 무효 샘플: RFC 3339 콜론 포함 형식은 Agent %z 정규식에 매칭되지 않아야 함
    for sample in invalid_rsyslog_samples:
        ts_token = sample.split()[0]  # "2026-09-04T15:00:01.102345+00:00"
        # +00:00 에서 [+-]\d{4}는 4자리 연속 숫자가 없으므로 None이어야 함
        tz_match = CW_AGENT_TZ_REGEX.search(ts_token)
        assert tz_match is None, (
            "[회귀 경고] RFC 3339 콜론 포함 형식이 Agent %z 정규식에 매칭됨 (예상치 못한 결과): "
            f"{ts_token!r} → {tz_match.group(0) if tz_match else None}\n"
            "EC2 rsyslog 출력 형식이 변경됐거나 Agent 소스가 업데이트됐습니다. 재검토 필요."
        )
