# CloudShield 단위 테스트: CloudWatch Logs 프로세서
# 소유자: 클라우드 B 담당
"""CloudWatch Logs 압축 해제기(cw_processor.py) 단위 테스트."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from collector.cw_processor import (
    SUBSCRIPTION_FILTER_SPEC,
    decode_cw_logs,
    matches_subscription_filter,
)
from contracts.events import CloudWatchLogsPayload, SyslogAuthEvent


def test_decode_cw_logs_success(sample_cw_event: dict[str, Any]) -> None:
    """CloudWatch Logs 페이로드 Gzip 압축 해제 및 로그 문자열 추출 검증.

    Why:
        CloudWatch Logs 구독 필터가 Lambda 함수로 전달한 실제 Base64/Gzip 압축
        페이로드(mock_cw_event.json)로부터 개별 로그 메시지 목록을 복원할 수 있는지 확인함.
    """
    lines = decode_cw_logs(sample_cw_event)
    assert isinstance(lines, list)
    assert len(lines) >= 1
    assert "Failed password" in lines[0]


def test_decode_cw_logs_empty_events() -> None:
    """logEvents가 비어 있는 정상 페이로드 인입 시 빈 리스트를 안전하게 반환하는지 검증."""
    empty_payload_model = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/auth-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-SSH-FailedPassword-Filter"],
        logEvents=[],
    )
    mock_event = {"awslogs": {"data": empty_payload_model.to_awslogs_data()}}
    lines = decode_cw_logs(mock_event)
    assert lines == []


def test_decode_cw_logs_invalid_inputs() -> None:
    """유효하지 않은 입력 페이로드 인입 시 예외 발생 검증.

    Why:
        비정상 인입 데이터로 인한 무음 실패(Silent Failure)를 방지하고
        명확한 에러 핸들링을 보장함.
    """
    # 1. 딕셔너리 타입이 아닌 경우 TypeError
    with pytest.raises(TypeError, match="payload는 dict 타입이어야 합니다"):
        decode_cw_logs("not-a-dict")  # type: ignore[arg-type]

    # 2. 'awslogs' 키 누락 시 KeyError
    with pytest.raises(KeyError, match="'awslogs'가 누락"):
        decode_cw_logs({"invalid_key": {}})

    # 3. 'data' 키 누락 시 KeyError
    with pytest.raises(KeyError, match="'data'가 누락"):
        decode_cw_logs({"awslogs": {}})

    # 4. 문자열이 아닌 data 필드 인입 시 ValueError
    with pytest.raises(ValueError, match="Base64 인코딩된 문자열"):
        decode_cw_logs({"awslogs": {"data": 12345}})  # type: ignore[dict-item]

    # 5. 손상된 Base64/Gzip 데이터 인입 시 ValueError
    with pytest.raises(ValueError, match="CloudWatch Logs"):
        decode_cw_logs({"awslogs": {"data": "invalid_base64_string!!!"}})


def test_subscription_filter_parameters_contract() -> None:
    """클라우드 A의 Terraform 모듈 연계용 구독 필터 정의 파라미터 명세 검증.

    Why:
        클라우드 B가 도출한 구독 필터 설정이 CloudWatch Agent 수집 명세의
        로그 그룹명과 일치하고, 의심 키워드('*Failed password*') 패턴을
        정확히 포함하는지 정적으로 검증함.
    """
    # 1. 필수 파라미터 키 검증
    required_keys = {"filter_name", "log_group_name", "filter_pattern", "destination_arn"}
    assert required_keys.issubset(SUBSCRIPTION_FILTER_SPEC.keys())

    # 2. 로그 그룹명이 CloudWatch Agent 수집 경로와 일치하는지 검증
    agent_config_path = Path("src/collector/amazon-cloudwatch-agent.json")
    assert agent_config_path.exists()
    agent_data = json.loads(agent_config_path.read_text(encoding="utf-8"))
    collect_list = agent_data["logs"]["logs_collected"]["files"]["collect_list"]
    expected_log_group = collect_list[0]["log_group_name"]

    assert SUBSCRIPTION_FILTER_SPEC["log_group_name"] == expected_log_group, (
        f"구독 필터 대상 로그 그룹({SUBSCRIPTION_FILTER_SPEC['log_group_name']})이 "
        f"CloudWatch Agent 수집 로그 그룹({expected_log_group})과 일치해야 합니다."
    )

    # 3. 필터 패턴 구문 유효성 검증
    expected_pattern = '[mon, day, timestamp, host, process, msg = "*Failed password*", ...]'
    assert SUBSCRIPTION_FILTER_SPEC["filter_pattern"] == expected_pattern


def test_matches_subscription_filter_simulation() -> None:
    """구독 필터 패턴([..., msg = "*Failed password*", ...]) 모의 매칭 검사.

    Why:
        실제 AWS 배포 전 로컬 테스트베드에서 정상 로그는 걸러내고
        SSH 실패 공격 로그만 선별하여 Lambda로 라우팅되는지 사전 검증함.
    """
    # 공격 시그니처 로그 (매칭 성공 대상)
    attack_line = (
        "Sep 03 14:20:01 target-ec2 sshd[12341]: "
        "Failed password for invalid user admin from 198.51.100.50 port 49152 ssh2"
    )
    assert matches_subscription_filter(attack_line) is True

    # 정상 접속 로그 (필터링 제외 대상)
    normal_line = (
        "2026-09-04T15:00:01.102345+0000 target-ec2 sshd[21001]: "
        "Accepted publickey for ubuntu from 192.0.2.10 port 52140 ssh2"
    )
    assert matches_subscription_filter(normal_line) is False

    # 기타 시스템 로그 (필터링 제외 대상)
    sudo_line = "Sep 03 14:21:00 target-ec2 sudo: pam_unix(sudo:session): session opened"
    assert matches_subscription_filter(sudo_line) is False

    # 엣지 케이스 (빈 문자열)
    assert matches_subscription_filter("") is False


def test_mock_lambda_subscription_filter_pipeline(sample_auth_log_lines: list[str]) -> None:
    """로그 수집 -> 구독 필터 -> Gzip 인코딩 -> 모의 Lambda 디코딩 -> Syslog 계약 파싱 파이프라인.

    Why:
        단일 10초 관통 대응 파이프라인의 1~2단계(수집 및 필터링 -> Lambda 인입)가
        실제 AWS 환경과 동일하게 압축/인코딩을 거쳐 무결하게 복원되는지 전체 연계를 증명함.
    """
    # 1. 구독 필터를 거쳐 'Failed password' 로그만 선별 (CloudWatch Subscription Filter 시뮬레이션)
    filtered_lines = [line for line in sample_auth_log_lines if matches_subscription_filter(line)]
    assert len(filtered_lines) >= 1, "모의 로그 내에 SSH 실패 이벤트가 1건 이상 존재해야 합니다."

    # 2. CloudWatch Logs가 Lambda로 전달하는 Gzip 압축 + Base64 인코딩 페이로드 모의 생성
    mock_cw_payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup=SUBSCRIPTION_FILTER_SPEC["log_group_name"],
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=[SUBSCRIPTION_FILTER_SPEC["filter_name"]],
        logEvents=[
            {"id": f"event-{idx}", "timestamp": 1725373200000 + idx, "message": line}
            for idx, line in enumerate(filtered_lines)
        ],
    )
    mock_lambda_event = {"awslogs": {"data": mock_cw_payload.to_awslogs_data()}}

    # 3. 모의 Lambda 환경에서 cw_processor.decode_cw_logs 실행
    decoded_lines = decode_cw_logs(mock_lambda_event)
    assert decoded_lines == filtered_lines

    # 4. 복원된 각 로그 라인이 공통 계약(SyslogAuthEvent)으로 무결하게 파싱되는지 최종 검증
    for line in decoded_lines:
        parsed = SyslogAuthEvent.parse_line(line)
        assert parsed is not None
        assert parsed.source_ip != ""
        assert "Failed password" in parsed.raw_message


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


def _render_rsyslog_log_from_template(
    template_str: str,
    dt: datetime,
    hostname: str = "target-ec2",
    syslogtag: str = "sshd[21001]:",
    msg: str = "Failed password for invalid user admin from 198.51.100.50 port 49152 ssh2",
) -> str:
    """rsyslog 템플릿 포맷 문자열을 datetime 및 시스템 필드로 렌더링.

    Why:
        init_target_server.sh의 배포 템플릿으로부터 실제 rsyslog 데몬이
        출력하는 것과 동일한 로그 라인을 합성하여 Agent 설정과의 정합성을 검증함.

    Constraints:
        rsyslog property replacer 옵션:
        - date-rfc3339: RFC 3339 콜론 포함 오프셋 (+00:00)
        - date-year/month/day/hour/minute/second/subseconds: ISO 일시 필드
        - date-tzoffsdirection/tzoffshour/tzoffsmin: 콜론 없는 오프셋 (+0000)
    """
    tz_offset = dt.utcoffset()
    if tz_offset is not None:
        total_seconds = int(tz_offset.total_seconds())
        sign = "+" if total_seconds >= 0 else "-"
        abs_seconds = abs(total_seconds)
        tz_hours = abs_seconds // 3600
        tz_mins = (abs_seconds % 3600) // 60
    else:
        sign, tz_hours, tz_mins = "+", 0, 0

    replacements = {
        "%TIMESTAMP:::date-rfc3339%": dt.isoformat(),
        "%TIMESTAMP:::date-year%": f"{dt.year:04d}",
        "%TIMESTAMP:::date-month%": f"{dt.month:02d}",
        "%TIMESTAMP:::date-day%": f"{dt.day:02d}",
        "%TIMESTAMP:::date-hour%": f"{dt.hour:02d}",
        "%TIMESTAMP:::date-minute%": f"{dt.minute:02d}",
        "%TIMESTAMP:::date-second%": f"{dt.second:02d}",
        "%TIMESTAMP:::date-subseconds%": f"{dt.microsecond:06d}",
        "%TIMESTAMP:::date-tzoffsdirection%": sign,
        "%TIMESTAMP:::date-tzoffshour%": f"{tz_hours:02d}",
        "%TIMESTAMP:::date-tzoffsmin%": f"{tz_mins:02d}",
        "%HOSTNAME%": hostname,
        "%syslogtag%": syslogtag,
        "%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%": f" {msg.strip()}",
        r"\n": "\n",
    }
    rendered = template_str
    for k, v in replacements.items():
        rendered = rendered.replace(k, v)
    return rendered


def _extract_deployed_rsyslog_format(script_path: Path) -> tuple[str, str]:
    """init_target_server.sh에서 배포되는 rsyslog 활성 템플릿명과 포맷 문자열을 추출.

    Why:
        테스트가 수동 하드코딩 샘플에 의존하지 않고, 실제 EC2 배포 스크립트의
        rsyslog 템플릿 정의와 기본 바인딩 설정을 직접 파싱하여 검증하도록 보장함.
    """
    content = script_path.read_text(encoding="utf-8")
    conf_pattern = (
        r"cat <<\s*['\"]?RSYSLOG_EOF['\"]?\s*>\s*"
        r"/etc/rsyslog\.d/00-cloudshield-timestamp\.conf\s*\n(.*?)\n\s*RSYSLOG_EOF"
    )
    conf_match = re.search(conf_pattern, content, re.DOTALL)
    assert conf_match is not None, (
        "init_target_server.sh 내 00-cloudshield-timestamp.conf 설정 블록이 존재해야 합니다."
    )
    conf_content = conf_match.group(1)

    default_match = re.search(
        r"^\s*\$ActionFileDefaultTemplate\s+(\S+)",
        conf_content,
        re.MULTILINE,
    )
    assert default_match is not None, (
        "00-cloudshield-timestamp.conf 내 $ActionFileDefaultTemplate 설정이 필요합니다."
    )
    active_tpl = default_match.group(1).strip()

    if active_tpl == "RSYSLOG_FileFormat":
        return (
            active_tpl,
            (
                "%TIMESTAMP:::date-rfc3339% %HOSTNAME% "
                "%syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\\n"
            ),
        )

    tpl_pattern = (
        rf'(?:template\s*\(\s*name="{active_tpl}"[^)]*string="([^"]+)"|'
        rf'\$template\s+{active_tpl}\s*,\s*"([^"]+)")'
    )
    tpl_match = re.search(tpl_pattern, conf_content)
    assert tpl_match is not None, (
        f"00-cloudshield-timestamp.conf 내에 {active_tpl} 템플릿 정의가 존재하지 않습니다."
    )
    format_str = tpl_match.group(1) or tpl_match.group(2)
    return (active_tpl, format_str)


def test_cloudwatch_agent_timestamp_z_directive_regex() -> None:
    """CloudWatch Agent %z 디렉티브 파싱 정규식과 rsyslog 배포 템플릿 정합성 회귀 테스트.

    Why:
        Agent 소스(timestamp.go)의 %z 디렉티브는 Go layout -0700에 매핑되며
        내부적으로 [+-]\\d{4} 정규식만 지원한다. RFC 3339 표준의 콜론 포함 오프셋(+00:00)은
        이 정규식에 매칭되지 않아 타임스탬프 추출 실패 → CloudWatch Logs의 인덱싱 시각이
        수집 시각으로 덮어씌워져 이벤트 발생 시각 추적이 불가능해진다.
        본 테스트는 init_target_server.sh의 실제 배포 rsyslog 템플릿으로부터 대표 로그를
        직접 렌더링하고, amazon-cloudwatch-agent.json의 timestamp_format과 연계하여
        시간대뿐 아니라 전체 타임스탬프와 발생 시각 정합성을 자동 검증한다.
        만약 배포 설정을 RSYSLOG_FileFormat(+00:00)으로 되돌리면 이 검증이 반드시 실패한다.

    Constraints:
        - Agent %z 지원 형식: +0000 (콜론 없는 4자리) — 매칭 성공
        - Agent %z 미지원 형식: +00:00 (RFC 3339 콜론 포함) — 매칭 실패
        - rsyslog 배포 템플릿: date-tzoffsdirection + date-tzoffshour + date-tzoffsmin 커스텀 템플릿

    Side-effects:
        init_target_server.sh의 rsyslog 템플릿 또는 Agent 설정 변경 시
        이 회귀 테스트가 즉각 실패하여 타임스탬프 파싱 불일치를 사전에 차단함.
        참고: https://github.com/aws/amazon-cloudwatch-agent/blob/main/internal/util/timestamp/timestamp.go
    """
    # Amazon CloudWatch Agent 내부 파싱 정규식 (timestamp.go 기준)
    # Directive: %z | Go layout: -0700 | Regex: [+-]\d{4}
    cw_agent_tz_regex = re.compile(r"[+-]\d{4}")
    cw_agent_full_ts_regex = re.compile(
        r"^\d{4}-\s{0,1}\d{1,2}-\s{0,1}\d{1,2}T\d{2}:\d{2}:\d{2}\.\d{1,9}[+-]\d{4}$"
    )

    # 1. JSON 설정에서 timestamp_format 추출 및 규격 검증
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

    # 2. init_target_server.sh에서 실제 배포되는 rsyslog 템플릿 추출
    script_path = Path("init_target_server.sh")
    assert script_path.exists(), "init_target_server.sh 파일이 존재해야 합니다."
    active_tpl, deployed_format = _extract_deployed_rsyslog_format(script_path)

    # 활성 템플릿이 RSYSLOG_FileFormat(콜론 포함 RFC 3339)이 아닌 커스텀 템플릿이어야 함
    assert active_tpl != "RSYSLOG_FileFormat", (
        "[회귀 실패] 배포 스크립트가 RSYSLOG_FileFormat을 활성 템플릿으로 사용하고 있습니다.\n"
        "CloudWatch Agent %z와 호환되는 콜론 없는 시간대(+0000) 커스텀 템플릿을 연결하세요."
    )

    # 3. 배포 템플릿에서 대표 로그 렌더링 (다양한 시간대: UTC, KST, EST)
    test_datetimes = [
        # UTC (+0000): 기본 시간대
        datetime(2026, 9, 4, 15, 0, 1, 102345, tzinfo=UTC),
        # KST (+0900): 양수 오프셋 시간대
        datetime(2026, 9, 14, 2, 30, 59, 1, tzinfo=timezone(timedelta(hours=9))),
        # EST (-0500): 음수 오프셋 시간대
        datetime(2026, 1, 1, 0, 0, 0, 999999, tzinfo=timezone(timedelta(hours=-5))),
    ]

    for expected_dt in test_datetimes:
        # 배포 템플릿으로부터 실제 rsyslog 출력 로그 라인 생성
        rendered_log = _render_rsyslog_log_from_template(deployed_format, expected_dt)
        ts_token = rendered_log.split()[0]

        # 3.1. Agent 전체 타임스탬프 파싱 정규식 매칭 검증
        assert cw_agent_full_ts_regex.match(ts_token) is not None, (
            f"[회귀 실패] 배포 템플릿 출력 타임스탬프가 Agent Go 정규식에 미매칭: {ts_token!r}"
        )

        # 3.2. Agent %z 디렉티브 정규식([+-]\\d{4}) 매칭 및 콜론 부재 단언
        tz_match = cw_agent_tz_regex.search(ts_token)
        assert tz_match is not None, (
            f"[회귀 실패] Agent %z 정규식이 배포 템플릿 타임존을 추출하지 못함: {ts_token!r}"
        )
        matched_tz = tz_match.group(0)
        assert ":" not in matched_tz, (
            f"[회귀 실패] 배포 템플릿 타임존에 콜론이 포함됨: {matched_tz!r} — Agent 파싱 불가"
        )

        # 3.3. 전체 타임스탬프 및 발생 시각(일시 + 오프셋) 정합성 최종 검증
        parsed_dt = datetime.strptime(ts_token, ts_format)
        assert parsed_dt == expected_dt, (
            f"추출된 발생 시각({parsed_dt})이 원본({expected_dt})과 일치하지 않습니다."
        )
        assert parsed_dt.year == expected_dt.year
        assert parsed_dt.month == expected_dt.month
        assert parsed_dt.day == expected_dt.day
        assert parsed_dt.hour == expected_dt.hour
        assert parsed_dt.minute == expected_dt.minute
        assert parsed_dt.second == expected_dt.second
        assert parsed_dt.microsecond == expected_dt.microsecond
        assert parsed_dt.utcoffset() == expected_dt.utcoffset()

    # 4. 회귀 방지 음성 검증 (배포 설정을 구 RSYSLOG_FileFormat으로 되돌리면 검증 실패 보장)
    legacy_format = (
        "%TIMESTAMP:::date-rfc3339% %HOSTNAME% "
        "%syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\\n"
    )
    legacy_sample = _render_rsyslog_log_from_template(legacy_format, test_datetimes[0])
    legacy_ts = legacy_sample.split()[0]  # "2026-09-04T15:00:01.102345+00:00"

    # RFC 3339 콜론 포함 형식은 Agent Go 정규식 및 %z 정규식 매칭에 반드시 실패해야 함
    assert cw_agent_full_ts_regex.match(legacy_ts) is None, (
        f"[회귀 경고] 구 RSYSLOG_FileFormat 타임스탬프가 Agent 정규식에 매칭됨: {legacy_ts!r}"
    )
    assert cw_agent_tz_regex.search(legacy_ts) is None, (
        f"[회귀 경고] 구 RSYSLOG_FileFormat 타임존이 Agent %z 정규식에 매칭됨: {legacy_ts!r}"
    )
