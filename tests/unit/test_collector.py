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
    LOG_GROUP_STREAM_MAPPING,
    NGINX_FAILURE_STATUS_CODES,
    NGINX_SUBSCRIPTION_FILTER_SPEC,
    SUBSCRIPTION_FILTER_SPEC,
    SUBSCRIPTION_FILTER_SPECS,
    decode_cw_logs,
    decode_nginx_cw_logs,
    deduplicate_log_events,
    matches_subscription_filter,
    route_cw_logs,
)
from contracts.events import (
    CloudWatchLogEvent,
    CloudWatchLogsPayload,
    NginxAccessLogEvent,
    SyslogAuthEvent,
)


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
        로그 그룹명과 일치하고, 비정형 정확 구문('"Failed password"') 패턴을
        정확히 명시하고 있는지 정적으로 검증함.
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

    # 3. 비정형 구문 필터 패턴 유효성 검증 (정확 구문 검색)
    expected_pattern = '"Failed password"'
    assert SUBSCRIPTION_FILTER_SPEC["filter_pattern"] == expected_pattern


def test_matches_subscription_filter_simulation() -> None:
    """구독 필터 패턴("Failed password") 모의 매칭 검사.

    Why:
        실제 AWS 배포 전 로컬 테스트베드에서 정상 로그는 걸러내고
        BSD 및 ISO 8601 포맷의 SSH 실패 공격 로그만 선별하여 Lambda로 라우팅되는지 사전 검증함.
    """
    # 1. BSD 포맷 공격 시그니처 로그 (매칭 성공 대상)
    bsd_attack_line = (
        "Sep 03 14:20:01 target-ec2 sshd[12341]: "
        "Failed password for invalid user admin from 198.51.100.50 port 49152 ssh2"
    )
    assert matches_subscription_filter(bsd_attack_line) is True

    # 2. ISO 8601 포맷 공격 시그니처 로그 (매칭 성공 대상)
    iso_attack_line = (
        "2026-09-04T15:00:01.102345+0000 target-ec2 sshd[21001]: "
        "Failed password for root from 198.51.100.50 port 52140 ssh2"
    )
    assert matches_subscription_filter(iso_attack_line) is True

    # 3. 정상 접속 로그 (필터링 제외 대상)
    normal_line = (
        "2026-09-04T15:00:01.102345+0000 target-ec2 sshd[21001]: "
        "Accepted publickey for ubuntu from 192.0.2.10 port 52140 ssh2"
    )
    assert matches_subscription_filter(normal_line) is False

    # 4. 기타 시스템 로그 (필터링 제외 대상)
    sudo_line = "Sep 03 14:21:00 target-ec2 sudo: pam_unix(sudo:session): session opened"
    assert matches_subscription_filter(sudo_line) is False

    # 5. 엣지 케이스 (빈 문자열)
    assert matches_subscription_filter("") is False


def test_subscription_filter_pattern_syntax_verification() -> None:
    """실제 설정된 비정형 구문 패턴 검증 및 구형 공백 분리 패턴의 결함 회귀 검증.

    Why:
        AWS CloudWatch Logs 공식 문서에 따르면, 공백 구분 필터([..., msg = ...])는
        공백으로 분리된 단일 토큰만 검사하므로 6번째 필드가 'Failed'인 실제 SSH 로그를
        매칭하지 못함. 실제 배포 패턴인 비정형 구문("Failed password")이
        BSD/ISO 8601 실패 로그를 정확히 포함하고, 정상 로그를 확실히 배제하는지 단언함.
    """
    actual_pattern = SUBSCRIPTION_FILTER_SPEC["filter_pattern"]
    assert actual_pattern == '"Failed password"', "배포 대상 패턴은 비정형 구문이어야 합니다."

    bsd_failed = (
        "Sep 03 14:20:01 target-ec2 sshd[12341]: "
        "Failed password for invalid user admin from 198.51.100.50 port 49152 ssh2"
    )
    iso_failed = (
        "2026-09-04T15:00:01.102345+0000 target-ec2 sshd[21001]: "
        "Failed password for root from 198.51.100.50 port 52140 ssh2"
    )
    accepted_log = (
        "Sep 03 14:20:05 target-ec2 sshd[12342]: "
        "Accepted password for deploy from 198.51.100.50 port 49154 ssh2"
    )
    sudo_log = "Sep 03 14:21:00 target-ec2 sudo: pam_unix(sudo:session): session opened"

    # [검증 1] 실제 설정 패턴("Failed password") 적용 시 정상 동작
    assert matches_subscription_filter(bsd_failed, pattern=actual_pattern) is True
    assert matches_subscription_filter(iso_failed, pattern=actual_pattern) is True
    assert matches_subscription_filter(accepted_log, pattern=actual_pattern) is False
    assert matches_subscription_filter(sudo_log, pattern=actual_pattern) is False

    # [검증 2] 구형 공백 구분 패턴 사용 시 매칭 실패 결함 입증
    # (6번째 토큰이 'Failed' 단일 단어이므로 'Failed password' 조건 만족 불가)
    flawed_pattern = '[mon, day, timestamp, host, process, msg = "*Failed password*", ...]'
    assert matches_subscription_filter(bsd_failed, pattern=flawed_pattern) is False, (
        "공백 구분 패턴은 msg 필드에 'Failed'만 할당되므로 매칭에 실패해야 합니다."
    )
    assert matches_subscription_filter(iso_failed, pattern=flawed_pattern) is False, (
        "ISO 8601 형식은 헤더 필드 인덱스가 달라 공백 구분 패턴 매칭에 실패해야 합니다."
    )


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


def test_cw_agent_config_nginx_and_buffering_tuning() -> None:
    """CloudWatch Agent JSON 설정의 Nginx 수집 경로, 포맷 및 버퍼링 튜닝 검증.

    Why:
        10초 관통 파이프라인의 수집 단계 목표 시간 예산(3초 이내) 충족을 위해
        Agent 메모리 버퍼 체류 상한(force_flush_interval)이 3초 이하로 튜닝되었는지 확인하고,
        /var/log/nginx/access.log가 중앙 로그 그룹으로 수집되도록 설정되었는지 검증함.
    """
    config_paths = [
        Path("amazon-cloudwatch-agent.json"),
        Path("src/collector/amazon-cloudwatch-agent.json"),
    ]

    for cfg_path in config_paths:
        assert cfg_path.exists(), f"{cfg_path} 파일이 존재해야 합니다."
        with cfg_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        logs_section = data.get("logs", {})
        # 1. 버퍼링 튜닝 검증 (수집 단계 목표 시간 예산 3초 이내 기준 체류 상한 튜닝)
        force_flush = logs_section.get("force_flush_interval")
        assert force_flush is not None, "logs.force_flush_interval 설정이 누락되었습니다."
        assert force_flush <= 3, f"force_flush_interval은 3초 이내여야 합니다: {force_flush}"

        # 2. 수집 파일 리스트 검증
        collect_list = (
            logs_section.get("logs_collected", {}).get("files", {}).get("collect_list", [])
        )
        assert len(collect_list) >= 2, "collect_list에 최소 2개(auth, nginx) 설정이 필요합니다."

        # auth.log 검증
        auth_entry = next((e for e in collect_list if "auth.log" in e.get("file_path", "")), None)
        assert auth_entry is not None, "auth.log 수집 항목이 누락되었습니다."
        assert auth_entry["log_group_name"] == "/cloudshield/target/auth-log"

        # nginx access.log 검증
        nginx_entry = next(
            (e for e in collect_list if "access.log" in e.get("file_path", "")), None
        )
        assert nginx_entry is not None, "nginx access.log 수집 항목이 누락되었습니다."
        assert nginx_entry["file_path"] == "/var/log/nginx/access.log"
        assert nginx_entry["log_group_name"] == "/cloudshield/target/nginx-access-log"
        assert nginx_entry["log_stream_name"] == "{instance_id}"
        assert nginx_entry["timestamp_format"] == "%d/%b/%Y:%H:%M:%S %z"

    # 루트와 src/collector/ 간 동기화 일치 단언
    root_content = Path("amazon-cloudwatch-agent.json").read_text(encoding="utf-8")
    src_content = Path("src/collector/amazon-cloudwatch-agent.json").read_text(encoding="utf-8")
    assert json.loads(root_content) == json.loads(src_content), (
        "루트와 src/collector/의 amazon-cloudwatch-agent.json 내용이 불일치합니다."
    )


def test_nginx_access_log_timestamp_format_parsing() -> None:
    """Nginx $time_local 포맷과 CW Agent %d/%b/%Y:%H:%M:%S %z 파싱 정합성 검증."""
    test_cases = [
        ("04/Sep/2026:15:00:01 +0000", datetime(2026, 9, 4, 15, 0, 1, tzinfo=UTC)),
        (
            "28/Sep/2026:20:45:10 +0900",
            datetime(2026, 9, 28, 20, 45, 10, tzinfo=timezone(timedelta(hours=9))),
        ),
        (
            "01/Jan/2026:00:00:00 -0500",
            datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone(timedelta(hours=-5))),
        ),
    ]

    for ts_str, expected_dt in test_cases:
        parsed = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        assert parsed == expected_dt
        assert parsed.utcoffset() == expected_dt.utcoffset()


def test_route_cw_logs_multi_stream() -> None:
    """CloudWatch Logs logGroup 경로에 따른 멀티 스트림 라우팅 분기 검증."""
    # 1. SSH auth-log 스트림 라우팅
    auth_msg = (
        "Sep 03 14:20:01 target-ec2 sshd[12341]: "
        "Failed password for invalid user admin from 198.51.100.50 port 49152 ssh2"
    )
    auth_payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/auth-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-SSH-FailedPassword-Filter"],
        logEvents=[
            CloudWatchLogEvent(
                id="ev-auth-1",
                timestamp=1788500000000,
                message=auth_msg,
            )
        ],
    )
    auth_event = {"awslogs": {"data": auth_payload.to_awslogs_data()}}
    auth_routed = route_cw_logs(auth_event)
    assert auth_routed["stream_type"] == "auth"
    assert auth_routed["log_group"] == "/cloudshield/target/auth-log"
    assert len(auth_routed["messages"]) == 1
    assert "Failed password" in auth_routed["messages"][0]
    assert auth_routed["dropped_duplicates"] == 0

    # 2. Nginx access-log 스트림 라우팅
    nginx_msg = (
        "198.51.100.77 - - [28/Sep/2026:11:52:38 +0000] "
        '"GET /admin HTTP/1.1" 401 150 "-" "curl/7.81.0" 0.002 "-"'
    )
    nginx_payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=[
            CloudWatchLogEvent(
                id="ev-nginx-1",
                timestamp=1788500001000,
                message=nginx_msg,
            )
        ],
    )
    nginx_event = {"awslogs": {"data": nginx_payload.to_awslogs_data()}}
    nginx_routed = route_cw_logs(nginx_event)
    assert nginx_routed["stream_type"] == "nginx"
    assert nginx_routed["log_group"] == "/cloudshield/target/nginx-access-log"
    assert len(nginx_routed["messages"]) == 1
    assert "GET /admin" in nginx_routed["messages"][0]
    assert nginx_routed["dropped_duplicates"] == 0

    # 3. 미등록 알 수 없는 logGroup 인입 시 격리
    unknown_payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/unknown/other-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=[],
        logEvents=[
            CloudWatchLogEvent(
                id="ev-unk-1",
                timestamp=1788500002000,
                message="unknown system message",
            )
        ],
    )
    unknown_event = {"awslogs": {"data": unknown_payload.to_awslogs_data()}}
    unknown_routed = route_cw_logs(unknown_event)
    assert unknown_routed["stream_type"] == "unknown"


def test_deduplicate_log_events_direct() -> None:
    """deduplicate_log_events 함수 단독 호출 멱등성 검증."""
    seen_ids = {"ev-existing"}
    events = [
        CloudWatchLogEvent(id="ev-existing", timestamp=1000, message="m1"),
        CloudWatchLogEvent(id="ev-new-1", timestamp=2000, message="m2"),
        CloudWatchLogEvent(id="ev-new-2", timestamp=3000, message="m3"),
    ]
    unique = deduplicate_log_events(events, seen_ids)
    assert len(unique) == 2
    assert [e.id for e in unique] == ["ev-new-1", "ev-new-2"]
    assert seen_ids == {"ev-existing", "ev-new-1", "ev-new-2"}


def test_route_cw_logs_at_least_once_idempotency() -> None:
    """At-least-once 재전송 시 중복 event.id 필터링 및 멱등성 보장 검증."""
    seen_ids: set[str] = set()

    # 1회차: 이벤트 3건 인입 (ev-1, ev-2, ev-3)
    batch_payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=[
            CloudWatchLogEvent(
                id="ev-1",
                timestamp=1788500001000,
                message='198.51.100.77 - - [28/Sep/2026:11:52:38 +0000] "GET /admin" 401',
            ),
            CloudWatchLogEvent(
                id="ev-2",
                timestamp=1788500002000,
                message='198.51.100.77 - - [28/Sep/2026:11:52:39 +0000] "GET /login" 401',
            ),
            CloudWatchLogEvent(
                id="ev-3",
                timestamp=1788500003000,
                message='198.51.100.77 - - [28/Sep/2026:11:52:40 +0000] "GET /shell" 404',
            ),
        ],
    )
    event1 = {"awslogs": {"data": batch_payload.to_awslogs_data()}}
    routed1 = route_cw_logs(event1, seen_event_ids=seen_ids)
    assert len(routed1["messages"]) == 3
    assert routed1["dropped_duplicates"] == 0
    assert seen_ids == {"ev-1", "ev-2", "ev-3"}

    # 2회차: 네트워크 재시도로 중복 이벤트 인입 (ev-2, ev-3 재인입 + 신규 ev-4)
    retry_payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=[
            CloudWatchLogEvent(
                id="ev-2",
                timestamp=1788500002000,
                message='198.51.100.77 - - [28/Sep/2026:11:52:39 +0000] "GET /login" 401',
            ),
            CloudWatchLogEvent(
                id="ev-3",
                timestamp=1788500003000,
                message='198.51.100.77 - - [28/Sep/2026:11:52:40 +0000] "GET /shell" 404',
            ),
            CloudWatchLogEvent(
                id="ev-4",
                timestamp=1788500004000,
                message='198.51.100.77 - - [28/Sep/2026:11:52:41 +0000] "GET /api" 401',
            ),
        ],
    )
    event2 = {"awslogs": {"data": retry_payload.to_awslogs_data()}}
    routed2 = route_cw_logs(event2, seen_event_ids=seen_ids)
    assert len(routed2["messages"]) == 1
    assert routed2["dropped_duplicates"] == 2
    assert routed2["event_ids"] == ["ev-4"]
    assert "GET /api" in routed2["messages"][0]
    assert seen_ids == {"ev-1", "ev-2", "ev-3", "ev-4"}


def test_nginx_subscription_filter_spec() -> None:
    """Nginx 구독 필터 파라미터 명세 및 공백 구분 필터 패턴 구조 검증.

    Why:
        nginx.conf의 cloudshield_combined 일반 텍스트 포맷에 맞춰
        CloudWatch Logs 공백 구분 필터 패턴(Space-delimited filter)으로
        401, 403, 404 상태 코드를 선별 구독하도록 정의되어 있는지 검증함.
    """
    assert NGINX_SUBSCRIPTION_FILTER_SPEC["filter_name"] == "CloudShield-Nginx-Access-Filter"
    assert (
        NGINX_SUBSCRIPTION_FILTER_SPEC["log_group_name"] == "/cloudshield/target/nginx-access-log"
    )
    pattern = NGINX_SUBSCRIPTION_FILTER_SPEC["filter_pattern"]
    assert pattern.startswith("[") and pattern.endswith("]")
    assert "status_code = 401" in pattern
    assert "status_code = 403" in pattern
    assert "status_code = 404" in pattern
    assert NGINX_SUBSCRIPTION_FILTER_SPEC["destination_type"] == "lambda"
    assert NGINX_FAILURE_STATUS_CODES == (401, 403, 404)

    assert "auth" in SUBSCRIPTION_FILTER_SPECS
    assert "nginx" in SUBSCRIPTION_FILTER_SPECS


def test_nginx_subscription_filter_matches_access_log() -> None:
    """실제 Nginx access.log 대표 라인에 대한 공백 구분 구독 필터 매칭/비매칭 검증.

    Why:
        리뷰어 지적사항: nginx.conf의 cloudshield_combined 일반 텍스트 형식
        ('$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent ...')
        으로 기록된 로그에서 401, 403, 404 침해 의심 로그만 선별하고 정상(200, 301, 500) 로그는
        제외되는지 로컬에서 철저히 검증함.
    """
    pattern = NGINX_SUBSCRIPTION_FILTER_SPEC["filter_pattern"]

    # 1. 401 Unauthorized (모의 L7 스프레잉/무차별 대입 타깃 로그 -> 매칭 성공)
    log_401 = (
        "198.51.100.77 - - [28/Sep/2026:14:00:00 +0000] "
        '"GET /admin HTTP/1.1" 401 150 "-" "curl/7.81.0" 0.002 "-"'
    )
    assert matches_subscription_filter(log_401, pattern=pattern) is True

    # 2. 403 Forbidden (디렉토리 인덱싱 차단 또는 WAF 차단 타깃 로그 -> 매칭 성공)
    log_403 = (
        "198.51.100.77 - - [28/Sep/2026:14:00:01 +0000] "
        '"GET /.env HTTP/1.1" 403 200 "-" "curl/7.81.0" 0.001 "-"'
    )
    assert matches_subscription_filter(log_403, pattern=pattern) is True

    # 3. 404 Not Found (디렉토리 스캐닝 타깃 로그 -> 매칭 성공)
    log_404 = (
        "198.51.100.77 - - [28/Sep/2026:14:00:02 +0000] "
        '"GET /wp-login.php HTTP/1.1" 404 125 "-" "curl/7.81.0" 0.001 "-"'
    )
    assert matches_subscription_filter(log_404, pattern=pattern) is True

    # 4. 200 OK (정상 웹 요청 -> 매칭 제외)
    log_200 = (
        "192.0.2.10 - - [28/Sep/2026:14:00:03 +0000] "
        '"GET /health HTTP/1.1" 200 45 "-" "kube-probe/1.28" 0.000 "-"'
    )
    assert matches_subscription_filter(log_200, pattern=pattern) is False

    # 5. 301 Moved Permanently (정상 리다이렉트 -> 매칭 제외)
    log_301 = (
        "192.0.2.10 - - [28/Sep/2026:14:00:04 +0000] "
        '"GET /login HTTP/1.1" 301 0 "-" "Mozilla/5.0" 0.001 "-"'
    )
    assert matches_subscription_filter(log_301, pattern=pattern) is False

    # 6. 500 Internal Server Error (서버 내부 오류 -> 4xx 필터 매칭 제외)
    log_500 = (
        "192.0.2.20 - - [28/Sep/2026:14:00:05 +0000] "
        '"POST /api/v1/checkout HTTP/1.1" 500 512 "-" "Mozilla/5.0" 0.120 "-"'
    )
    assert matches_subscription_filter(log_500, pattern=pattern) is False

    # 상태 코드와 같은 숫자가 URI에만 포함된 경우에는 상태 필드 조건으로 매칭하면 안 됨.
    log_uri_contains_status = (
        "198.51.100.77 - - [28/Sep/2026:11:52:43 +0000] "
        '"GET /archive/404/report HTTP/1.1" 200 150 "-" "curl/7.81.0" 0.002 "-"'
    )
    assert matches_subscription_filter(log_uri_contains_status, pattern=pattern) is False


def test_nginx_subscription_filter_regression_against_json_pattern() -> None:
    """구 JSON 패턴 사용 시 일반 텍스트 Nginx access.log 미매칭 결함 회귀 검증.

    Why:
        구형 필터 패턴 '{ ($.status = 401) || ($.status = 403) || ($.status = 404) }'은
        JSON 필드를 조회하므로 cloudshield_combined 일반 텍스트 로그를 매칭하지 못함을
        단언하여 공백 구분 필터 패턴의 도입 당위성을 입증함.
    """
    flawed_json_pattern = "{ ($.status = 401) || ($.status = 403) || ($.status = 404) }"
    log_401 = (
        "198.51.100.77 - - [28/Sep/2026:14:00:00 +0000] "
        '"GET /admin HTTP/1.1" 401 150 "-" "curl/7.81.0" 0.002 "-"'
    )
    assert matches_subscription_filter(log_401, pattern=flawed_json_pattern) is False, (
        "일반 텍스트 Nginx access.log는 JSON 패턴에 매칭되지 않아야 합니다."
    )


def test_route_cw_logs_new_execution_environment_reingestion_limitation() -> None:
    """새 실행 환경(Cold Start) 또는 세트 미제공 시 동일 event.id 재인입 한계 검증.

    Why:
        리뷰어 지적사항: route_cw_logs의 seen_event_ids는 프로세스 메모리에만 존재하므로,
        새로운 Lambda 실행 환경 기동 또는 seen_event_ids가 None인 경우 동일한 event.id가
        재인입되었을 때 필터링되지 않고 재처리되는 인메모리 방식의 경계 조건을 명시적으로 검증함.
        (향후 클라우드 A의 DynamoDB 원자적 상태 테이블 연계 필요성 증빙)
    """
    test_event_msg = '198.51.100.77 - - [28/Sep/2026:11:52:38 +0000] "GET /admin" 401'
    batch_payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=[
            CloudWatchLogEvent(
                id="ev-reingest-1",
                timestamp=1788500001000,
                message=test_event_msg,
            ),
        ],
    )
    raw_event = {"awslogs": {"data": batch_payload.to_awslogs_data()}}

    # 1. 1차 실행 컨테이너(Worker 1): 인메모리 세트로 정상 수신
    worker1_seen_ids: set[str] = set()
    res1 = route_cw_logs(raw_event, seen_event_ids=worker1_seen_ids)
    assert len(res1["messages"]) == 1
    assert res1["dropped_duplicates"] == 0
    assert "ev-reingest-1" in worker1_seen_ids

    # 2. 동일 컨테이너 재시도: 세트가 공유되므로 정상적으로 중복 필터링
    res1_retry = route_cw_logs(raw_event, seen_event_ids=worker1_seen_ids)
    assert len(res1_retry["messages"]) == 0
    assert res1_retry["dropped_duplicates"] == 1

    # 3. 새 실행 환경(Worker 2 / Cold Start): 메모리 세트 소실로 동일 ID 재인입 (한계 검증)
    worker2_fresh_seen_ids: set[str] = set()
    res2 = route_cw_logs(raw_event, seen_event_ids=worker2_fresh_seen_ids)
    assert len(res2["messages"]) == 1, (
        "새 실행 환경에서는 인메모리 세트가 소실되므로 동일 이벤트가 재처리됩니다."
    )
    assert res2["dropped_duplicates"] == 0

    # 4. seen_event_ids가 미제공(None)된 경우에도 중복 필터링 없이 그대로 통과
    res_none = route_cw_logs(raw_event, seen_event_ids=None)
    assert len(res_none["messages"]) == 1
    assert res_none["dropped_duplicates"] == 0


def test_decode_nginx_cw_logs_success() -> None:
    """CloudWatch Logs 압축 페이로드에서 Nginx L7 웹 접근 로그 디코딩 및 정형 계약 모델 변환 검증.

    Why:
        수집 단계(CloudWatch Logs Subscription Filter -> Lambda)에서 Base64/Gzip 압축된
        이진 페이로드를 단일 패스로 디코딩하고, Pydantic 불변 객체(NginxAccessLogEvent) 목록으로
        역직렬화하여 후속 룰 엔진에 안전하게 전달할 수 있는지 확인함.
    """
    line1 = (
        "198.51.100.77 - - [28/Sep/2026:14:00:00 +0000] "
        '"GET /admin HTTP/1.1" 401 150 "-" "curl/7.81.0" 0.002 "-"'
    )
    line2 = (
        "203.0.113.50 - - [28/Sep/2026:14:00:01 +0000] "
        '"POST /api/v1/login HTTP/1.1" 403 200 "https://example.com" "Mozilla/5.0" 0.015 "-"'
    )
    payload_model = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=[
            CloudWatchLogEvent(id="ev-nginx-1", timestamp=1788500000000, message=line1),
            CloudWatchLogEvent(id="ev-nginx-2", timestamp=1788500001000, message=line2),
        ],
    )
    mock_event = {"awslogs": {"data": payload_model.to_awslogs_data()}}

    events = decode_nginx_cw_logs(mock_event)
    assert isinstance(events, list)
    assert len(events) == 2
    assert all(isinstance(e, NginxAccessLogEvent) for e in events)

    # 1번째 이벤트 정합성 검증
    assert events[0].source_ip == "198.51.100.77"
    assert events[0].method == "GET"
    assert events[0].uri == "/admin"
    assert events[0].status_code == 401
    assert events[0].response_time == 0.002
    assert events[0].user_agent == "curl/7.81.0"

    # 2번째 이벤트 정합성 검증
    assert events[1].source_ip == "203.0.113.50"
    assert events[1].method == "POST"
    assert events[1].uri == "/api/v1/login"
    assert events[1].status_code == 403
    assert events[1].response_time == 0.015
    assert events[1].user_agent == "Mozilla/5.0"


def test_decode_nginx_cw_logs_noisy_and_empty_events() -> None:
    """Nginx 로그 규격과 일치하지 않는 노이즈/손상 라인 필터링 및 빈 배치 처리 검증.

    Why:
        수집 로그 스트림에 비정상 문자열, 공백 라인, 또는 SSH auth 로그가 혼입되더라도
        NginxAccessLogEvent.parse_line()의 안전 반환(None) 처리를 통해
        유효한 Nginx 접근 로그만 격리 추출됨을 단언함.
    """
    valid_nginx_line = (
        "198.51.100.77 - - [28/Sep/2026:14:00:00 +0000] "
        '"GET /shell.php HTTP/1.1" 404 125 "-" "curl/7.81.0" 0.001 "-"'
    )
    ssh_noise_line = (
        "Sep 03 14:20:01 target-ec2 sshd[12341]: "
        "Failed password for invalid user admin from 198.51.100.50 port 49152 ssh2"
    )
    corrupted_line = "THIS IS NOT AN NGINX LOG LINE"

    payload_model = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=[
            CloudWatchLogEvent(id="ev-1", timestamp=1788500000000, message=valid_nginx_line),
            CloudWatchLogEvent(id="ev-2", timestamp=1788500001000, message="   "),
            CloudWatchLogEvent(id="ev-3", timestamp=1788500002000, message=ssh_noise_line),
            CloudWatchLogEvent(id="ev-4", timestamp=1788500003000, message=corrupted_line),
        ],
    )
    mock_event = {"awslogs": {"data": payload_model.to_awslogs_data()}}

    events = decode_nginx_cw_logs(mock_event)
    assert len(events) == 1
    assert events[0].source_ip == "198.51.100.77"
    assert events[0].uri == "/shell.php"
    assert events[0].status_code == 404

    # 빈 logEvents 인입 시 빈 리스트 안전 반환 검증
    empty_payload_model = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=[],
    )
    empty_event = {"awslogs": {"data": empty_payload_model.to_awslogs_data()}}
    assert decode_nginx_cw_logs(empty_event) == []


def test_decode_nginx_cw_logs_invalid_inputs() -> None:
    """유효하지 않은 입력 페이로드 인입 시 decode_nginx_cw_logs 예외 격리 검증."""
    # 1. 딕셔너리 타입이 아닌 경우 TypeError
    with pytest.raises(TypeError, match="payload는 dict 타입이어야 합니다"):
        decode_nginx_cw_logs(["not-a-dict"])  # type: ignore[arg-type]

    # 2. 'awslogs' 키 누락 시 KeyError
    with pytest.raises(KeyError, match="'awslogs'가 누락"):
        decode_nginx_cw_logs({"wrong_key": 123})

    # 3. 'data' 키 누락 시 KeyError
    with pytest.raises(KeyError, match="'data'가 누락"):
        decode_nginx_cw_logs({"awslogs": {}})

    # 4. 문자열이 아닌 data 필드 인입 시 ValueError
    with pytest.raises(ValueError, match="Base64 인코딩된 문자열"):
        decode_nginx_cw_logs({"awslogs": {"data": None}})  # type: ignore[dict-item]

    # 5. 손상된 Base64 데이터 인입 시 ValueError
    with pytest.raises(ValueError, match="CloudWatch Logs"):
        decode_nginx_cw_logs({"awslogs": {"data": "corrupted@@@data"}})


def test_route_cw_logs_with_parsed_events_multi_stream() -> None:
    """route_cw_logs 호출 시 스트림 유형별 parsed_events 정형 모델 파싱 일관성 검증.

    Why:
        오케스트레이터가 메시지 문자열(messages)뿐만 아니라 이미 정형화된 Pydantic 불변 객체
        (auth: SyslogAuthEvent, nginx: NginxAccessLogEvent)를 직접 전달받아
        각 도메인별 룰 엔진으로 즉시 분기할 수 있도록 지원함.
    """
    # 1. SSH Auth 스트림 인입
    auth_line = (
        "Sep 03 14:20:01 target-ec2 sshd[12341]: "
        "Failed password for invalid user admin from 198.51.100.50 port 49152 ssh2"
    )
    auth_payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/auth-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-SSH-FailedPassword-Filter"],
        logEvents=[CloudWatchLogEvent(id="ev-auth-1", timestamp=1788500000000, message=auth_line)],
    )
    auth_event = {"awslogs": {"data": auth_payload.to_awslogs_data()}}
    auth_result = route_cw_logs(auth_event)

    assert auth_result["stream_type"] == "auth"
    assert "parsed_events" in auth_result
    assert len(auth_result["parsed_events"]) == 1
    assert isinstance(auth_result["parsed_events"][0], SyslogAuthEvent)
    assert auth_result["parsed_events"][0].source_ip == "198.51.100.50"
    assert auth_result["parsed_events"][0].username == "admin"

    # 2. Nginx Web 스트림 인입
    nginx_line = (
        "198.51.100.77 - - [28/Sep/2026:14:00:00 +0000] "
        '"GET /wp-login.php HTTP/1.1" 404 125 "-" "curl/7.81.0" 0.001 "-"'
    )
    nginx_payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=[
            CloudWatchLogEvent(id="ev-nginx-1", timestamp=1788500000000, message=nginx_line)
        ],
    )
    nginx_event = {"awslogs": {"data": nginx_payload.to_awslogs_data()}}
    nginx_result = route_cw_logs(nginx_event)

    assert nginx_result["stream_type"] == "nginx"
    assert "parsed_events" in nginx_result
    assert len(nginx_result["parsed_events"]) == 1
    assert isinstance(nginx_result["parsed_events"][0], NginxAccessLogEvent)
    assert nginx_result["parsed_events"][0].source_ip == "198.51.100.77"
    assert nginx_result["parsed_events"][0].uri == "/wp-login.php"
    assert nginx_result["parsed_events"][0].status_code == 404

    # 3. 미등록 Unknown 스트림 인입 시 격리 및 빈 parsed_events 반환
    unknown_payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/unknown/other-log",
        logStream="i-0abcd1234ef56789a",
        subscriptionFilters=[],
        logEvents=[
            CloudWatchLogEvent(id="ev-unk-1", timestamp=1788500000000, message="unknown msg")
        ],
    )
    unknown_event = {"awslogs": {"data": unknown_payload.to_awslogs_data()}}
    unknown_result = route_cw_logs(unknown_event)

    assert unknown_result["stream_type"] == "unknown"
    assert unknown_result["parsed_events"] == []


def test_route_cw_logs_deployed_and_compat_paths() -> None:
    """배포 표준 설정 및 호환용 CloudWatch Agent 로그 그룹 경로 매핑 정합성 검증.

    Why:
        amazon-cloudwatch-agent.json에 정의된 배포 표준 수집 경로
        (/cloudshield/target/auth-log 및 /cloudshield/target/nginx-access-log)와
        추가 호환/대체 경로(/aws/ec2/target-server/auth 및 /aws/ec2/target-server/nginx/access)가
        오케스트레이터 라우터에서 'auth'와 'nginx'로 정확히 분류되는지 확인함.
    """
    # 1. 배포 설정 파일(amazon-cloudwatch-agent.json) 실제 경로 매핑 검증
    config_path = Path("src/collector/amazon-cloudwatch-agent.json")
    with config_path.open("r", encoding="utf-8") as f:
        config_data = json.load(f)
    collect_list = (
        config_data.get("logs", {})
        .get("logs_collected", {})
        .get("files", {})
        .get("collect_list", [])
    )
    deployed_log_groups = {item["log_group_name"] for item in collect_list}
    assert "/cloudshield/target/auth-log" in deployed_log_groups
    assert "/cloudshield/target/nginx-access-log" in deployed_log_groups
    assert LOG_GROUP_STREAM_MAPPING["/cloudshield/target/auth-log"] == "auth"
    assert LOG_GROUP_STREAM_MAPPING["/cloudshield/target/nginx-access-log"] == "nginx"

    # 2. 추가 호환/대체 경로 매핑 검증
    assert LOG_GROUP_STREAM_MAPPING["/aws/ec2/target-server/auth"] == "auth"
    assert LOG_GROUP_STREAM_MAPPING["/aws/ec2/target-server/nginx/access"] == "nginx"

    # 3. 배포 표준 경로 기반 Nginx 이벤트 라우팅
    nginx_line = (
        "198.51.100.99 - - [28/Sep/2026:14:05:00 +0000] "
        '"GET /api/v1/test HTTP/1.1" 401 100 "-" "test-agent" 0.003 "-"'
    )
    payload_model = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream="i-deployed-ec2-instance",
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=[
            CloudWatchLogEvent(
                id="ev-dep-1",
                timestamp=1788500000000,
                message=nginx_line,
            )
        ],
    )
    routed = route_cw_logs({"awslogs": {"data": payload_model.to_awslogs_data()}})
    assert routed["stream_type"] == "nginx"
    assert len(routed["parsed_events"]) == 1
    assert routed["parsed_events"][0].source_ip == "198.51.100.99"

    # 4. 호환 경로 기반 Nginx 이벤트 라우팅
    payload_compat = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/aws/ec2/target-server/nginx/access",
        logStream="i-compat-ec2-instance",
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=[
            CloudWatchLogEvent(
                id="ev-compat-1",
                timestamp=1788500000000,
                message=nginx_line,
            )
        ],
    )
    routed_compat = route_cw_logs({"awslogs": {"data": payload_compat.to_awslogs_data()}})
    assert routed_compat["stream_type"] == "nginx"
    assert len(routed_compat["parsed_events"]) == 1
    assert routed_compat["parsed_events"][0].source_ip == "198.51.100.99"
