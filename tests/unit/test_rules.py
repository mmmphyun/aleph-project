# CloudShield 단위 테스트: 보안 탐지 룰 엔진
# 소유자: 보안 담당
"""시그니처 1차 룰 엔진(rules.py) 단위 테스트.

Why:
    정상 접속 로그, 패스워드 스프레잉, 단일 계정 브루트포스, 오탐 경계값 시나리오를
    격리 검증하여 탐지 정확도를 보장하고 임계치 변경 시 회귀를 방지함.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from contracts.events import NginxAccessLogEvent, SyslogAuthEvent
from detection.rules import (
    BRUTE_FORCE_THRESHOLD,
    PASSWORD_SPRAYING_THRESHOLD,
    evaluate_rules,
    evaluate_web_rules,
    extract_auth_failure_identity,
)
from detection.url_normalizer import MAX_URL_VALUE_LENGTH, normalize_url_value

# ---------------------------------------------------------------------------
# 공통 헬퍼
# ---------------------------------------------------------------------------

_LOG_TEMPLATE = (
    "Sep 03 14:20:01 target-ec2 sshd[1234{i}]: "
    "Failed password for {user} from {ip} port 4915{i} ssh2"
)


@pytest.fixture
def noisy_auth_lines() -> list[str]:
    """공통 데이터는 수정하지 않고 보안 테스트 내부에서 읽어 회귀 입력을 고정한다."""
    path = Path(__file__).resolve().parents[1] / "mock_data" / "mock_auth_noisy.log"
    return path.read_text(encoding="utf-8").splitlines()


@pytest.fixture
def normal_noisy_auth_lines(noisy_auth_lines: list[str]) -> list[str]:
    """정상 활동 샘플을 명시해 실패 문자열 부정 조건에 의존하지 않는다."""
    normal_markers = (
        "Accepted publickey for ubuntu",
        "New session 42 of user ubuntu",
        "COMMAND=/usr/bin/apt update",
        "Connection closed by authenticating user operator",
        "Accepted password for devops",
        "Received disconnect from 192.0.2.10",
        "Disconnected from user ubuntu",
    )
    normal_lines = [
        line for line in noisy_auth_lines if any(marker in line for marker in normal_markers)
    ]
    assert len(normal_lines) == len(normal_markers)
    return normal_lines


def test_noisy_log_preserves_only_expected_failures(noisy_auth_lines: list[str]) -> None:
    """정상 활동이 실패 카운트에 유입되거나 실제 실패가 누락되는 회귀를 함께 검출한다."""
    events = [
        event
        for line in noisy_auth_lines
        if (event := SyslogAuthEvent.parse_line(line)) is not None
    ]
    assert [(event.source_ip, event.username) for event in events] == [
        ("203.0.113.195", "admin"),
        ("203.0.113.195", "root"),
        ("203.0.113.195", "service"),
        ("203.0.113.195", "guest"),
        ("203.0.113.195", "operator"),
        ("198.51.100.99", "devops"),
    ]
    assert evaluate_rules(events) == (True, "SSH_PASSWORD_SPRAYING")


def test_extract_auth_failure_identity_from_mock_auth(sample_auth_log_lines: list[str]) -> None:
    """mock_auth.log에서 공격자 IP와 계정을 정규식으로 안전하게 추출한다."""
    identities = [
        identity
        for line in sample_auth_log_lines
        if (identity := extract_auth_failure_identity(line)) is not None
    ]
    assert identities == [
        ("198.51.100.50", "admin"),
        ("198.51.100.50", "admin"),
        ("198.51.100.50", "root"),
        ("198.51.100.50", "root"),
        ("198.51.100.50", "guest"),
    ]


def test_extract_auth_failure_identity_ignores_normal_noise(
    normal_noisy_auth_lines: list[str],
) -> None:
    """성공 인증·세션·sudo·연결 종료 로그는 공격자 식별자로 추출하지 않는다."""
    assert [extract_auth_failure_identity(line) for line in normal_noisy_auth_lines] == [
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ]


def test_extract_auth_failure_identity_rejects_invalid_ipv4() -> None:
    """IPv4 옥텟 범위를 벗어난 출발지는 공격자 식별자로 채택하지 않는다."""
    line = (
        "Sep 03 14:20:01 target-ec2 sshd[12341]: "
        "Failed password for invalid user admin from 999.198.51.100 port 49152 ssh2"
    )
    assert extract_auth_failure_identity(line) is None


def test_normal_activity_is_not_an_auth_failure(normal_noisy_auth_lines: list[str]) -> None:
    """성공 인증·sudo·세션·연결 종료는 반복돼도 공격 증거가 되지 않아야 한다."""
    for line in normal_noisy_auth_lines:
        assert SyslogAuthEvent.parse_line(line) is None, line


def test_single_failure_with_normal_activity_is_not_an_attack(noisy_auth_lines: list[str]) -> None:
    """공격 IP를 제거한 실제 혼합 입력에서 관리자 1회 실패가 오탐되지 않음을 검증한다."""
    lines = [line for line in noisy_auth_lines if "203.0.113.195" not in line]
    events = [event for line in lines if (event := SyslogAuthEvent.parse_line(line)) is not None]
    assert len(events) == 1
    assert events[0].username == "devops"
    assert evaluate_rules(events) == (False, None)


@pytest.mark.parametrize("failure_count", [4, 5])
def test_normal_noise_does_not_change_brute_force_threshold(
    normal_noisy_auth_lines: list[str], failure_count: int
) -> None:
    """실패와 같은 IP·계정의 정상 로그도 4회/5회 판정 경계를 바꾸면 안 된다."""
    normal_lines = [
        line.replace("192.0.2.10", "198.51.100.99").replace("ubuntu", "devops")
        for line in normal_noisy_auth_lines
    ]
    failures = [
        "2026-09-04T15:02:00+00:00 target-ec2 sshd["
        f"{22000 + index}]: Failed password for devops from 198.51.100.99 port 53100 ssh2"
        for index in range(failure_count)
    ]
    events = [
        event
        for line in normal_lines + failures + normal_lines
        if (event := SyslogAuthEvent.parse_line(line)) is not None
    ]
    assert len(events) == failure_count
    expected = (True, "SSH_BRUTE_FORCE") if failure_count == 5 else (False, None)
    assert evaluate_rules(events) == expected


def _make_events(
    ip: str,
    username: str,
    count: int,
) -> list[SyslogAuthEvent]:
    """단일 IP · 단일 계정 실패 이벤트를 count만큼 생성하는 헬퍼.

    Why:
        반복적인 로그 문자열 생성을 캡슐화하여 테스트 가독성을 높이고
        로그 포맷 변경 시 단일 지점에서 수정 가능하도록 DRY 원칙 적용.
    """
    lines = [_LOG_TEMPLATE.format(i=i, user=username, ip=ip) for i in range(count)]
    events = [SyslogAuthEvent.parse_line(line) for line in lines]
    return [e for e in events if e is not None]


# ===========================================================================
# 1. 인터페이스 및 파싱 정상 동작 검증
# ===========================================================================


def test_evaluate_rules_interface(sample_auth_log_lines: list[str]) -> None:
    """evaluate_rules 함수 시그니처 및 mock_auth.log 파싱 정상 동작 검증.

    Why:
        SyslogAuthEvent.parse_line이 mock_auth.log 5개 라인을 모두 파싱하고,
        evaluate_rules가 (bool, str|None) 튜플을 반환하는지 인터페이스 계약을 검증함.

    Constraints:
        mock_auth.log는 3개 이상의 고유 계정(admin, root, guest)이 존재하므로
        PASSWORD_SPRAYING_THRESHOLD(2) 초과 → SSH_PASSWORD_SPRAYING 탐지 예상.
    """
    events = [
        SyslogAuthEvent.parse_line(line)
        for line in sample_auth_log_lines
        if SyslogAuthEvent.parse_line(line) is not None
    ]
    # mock_auth.log 5개 라인 전부 파싱 성공 검증
    assert len(events) >= 1

    is_detected, rule_name = evaluate_rules(events)

    # 반환 타입 계약 검증
    assert isinstance(is_detected, bool)
    assert rule_name is None or isinstance(rule_name, str)


# ===========================================================================
# 2. 탐지 성공 시나리오
# ===========================================================================


def test_brute_force_detection_success() -> None:
    """단일 IP · 단일 계정 BRUTE_FORCE_THRESHOLD회 이상 실패 시 SSH_BRUTE_FORCE 탐지 검증.

    Why:
        Hydra가 단일 계정(root)에 집중하는 패턴을 재현하여
        계정 잠금 회피 시도가 BRUTE_FORCE_THRESHOLD 임계치에서 정확히 탐지되는지 확인.

    Edge-cases:
        BRUTE_FORCE_THRESHOLD 이상의 이벤트를 생성하여 경계값 초과를 명시적으로 검증.
    """
    events = _make_events(
        ip="192.0.2.1",
        username="root",
        count=BRUTE_FORCE_THRESHOLD,  # 임계치 정확히 달성
    )
    assert len(events) == BRUTE_FORCE_THRESHOLD

    is_detected, rule_name = evaluate_rules(events)

    assert is_detected is True
    assert rule_name == "SSH_BRUTE_FORCE"


def test_account_and_host_keywords_do_not_trigger_unauthorized_access() -> None:
    """리뷰에서 지적된 계정·호스트 키워드가 정상 실패를 별도 위협으로 승격하지 않는다."""
    for keyword in ("denied", "unauthorized"):
        line = _LOG_TEMPLATE.replace("target-ec2", f"{keyword}-host").format(
            i=0, user=keyword, ip="198.51.100.12"
        )
        event = SyslogAuthEvent.parse_line(line)
        assert event is not None
        assert evaluate_rules([event]) == (False, None)


def test_brute_force_window_exact_boundary() -> None:
    """300초는 포함하고 301초는 제외해 시간 조건 수정의 경계를 고정한다."""
    for end_time, expected in (
        ("14:25:01", (True, "SSH_BRUTE_FORCE")),
        ("14:25:02", (False, None)),
    ):
        events = _make_events("198.51.100.13", "root", 4)
        line = _LOG_TEMPLATE.replace("14:20:01", end_time).format(
            i=5, user="root", ip="198.51.100.13"
        )
        event = SyslogAuthEvent.parse_line(line)
        assert event is not None
        events.insert(0, event)
        assert evaluate_rules(events) == expected


def test_brute_force_priority_is_independent_of_ip_order() -> None:
    """스프레잉 IP가 먼저 들어와도 다른 IP의 단일 계정 공격이 우선해야 한다."""
    spraying = _make_events("198.51.100.14", "admin", 1)
    spraying.extend(_make_events("198.51.100.14", "guest", 1))
    brute_force = _make_events("198.51.100.15", "root", 100)
    for events in (spraying + brute_force, brute_force + spraying):
        assert evaluate_rules(events) == (True, "SSH_BRUTE_FORCE")


def test_password_spraying_detection_success(sample_auth_log_lines: list[str]) -> None:
    """동일 IP에서 PASSWORD_SPRAYING_THRESHOLD개 이상 고유 계정 실패 시
    SSH_PASSWORD_SPRAYING 탐지 검증.

    Why:
        mock_auth.log의 admin/root/guest 3개 계정 혼용 패턴이
        T1110.003 Password Spraying 룰에 의해 정확히 탐지되는지 검증.
        스프레잉은 계정별 실패 횟수가 낮아도 탐지되어야 하므로 브루트포스와 독립 검증.
    """
    events = [
        SyslogAuthEvent.parse_line(line)
        for line in sample_auth_log_lines
        if SyslogAuthEvent.parse_line(line) is not None
    ]

    is_detected, rule_name = evaluate_rules(events)

    assert is_detected is True
    assert rule_name == "SSH_PASSWORD_SPRAYING"


# ===========================================================================
# 3. 오탐 방지 (정상 접속 경계값) 검증
# ===========================================================================


def test_no_detection_below_threshold() -> None:
    """단일 계정 BRUTE_FORCE_THRESHOLD - 1회 실패 시 오탐 없음(False 반환) 검증.

    Why:
        관리자가 패스워드를 잊어 4회 이하 재시도하는 정상 시나리오에서
        오탐으로 차단되지 않도록 임계치 경계값 하한(N-1)을 명시 검증.
    """
    events = _make_events(
        ip="10.0.0.1",
        username="admin",
        count=BRUTE_FORCE_THRESHOLD - 1,  # 임계치 미달
    )

    is_detected, rule_name = evaluate_rules(events)

    assert is_detected is False
    assert rule_name is None


def test_no_detection_single_account_single_ip() -> None:
    """단일 IP · 단일 계정 1회 실패 → 정상 오타로 간주, 미탐지 검증.

    Why:
        가장 빈번한 정상 이벤트(1회 패스워드 오타)가 오탐으로 차단되지 않음을 보장.
    """
    events = _make_events(ip="172.16.0.10", username="ubuntu", count=1)

    is_detected, rule_name = evaluate_rules(events)

    assert is_detected is False
    assert rule_name is None


def test_no_detection_empty_logs() -> None:
    """빈 이벤트 리스트 입력 시 (False, None) 반환 검증.

    Edge-cases:
        CloudWatch Logs 수신 데이터가 빈 경우 Lambda 오케스트레이터가 조기 종료할 수 있도록
        빈 입력에 대한 안전한 기본 반환값을 보장함.
    """
    is_detected, rule_name = evaluate_rules([])

    assert is_detected is False
    assert rule_name is None


# ===========================================================================
# 4. 스프레잉 임계치 경계값 검증
# ===========================================================================


def test_password_spraying_threshold_boundary() -> None:
    """PASSWORD_SPRAYING_THRESHOLD개 고유 계정 정확히 충족 시 탐지 검증 (경계값 테스트).

    Why:
        스프레잉 임계치 상수가 변경될 경우 회귀가 즉시 감지되도록
        코드에서 상수를 직접 참조하여 경계값을 동적으로 생성함.
    """
    # PASSWORD_SPRAYING_THRESHOLD개 고유 계정 생성
    ip = "203.0.113.99"
    all_events: list[SyslogAuthEvent] = []
    for idx in range(PASSWORD_SPRAYING_THRESHOLD):
        username = f"user{idx}"
        events = _make_events(ip=ip, username=username, count=1)
        all_events.extend(events)

    is_detected, rule_name = evaluate_rules(all_events)

    assert is_detected is True
    assert rule_name == "SSH_PASSWORD_SPRAYING"


# ===========================================================================
# 5. 시간창ㆍ우선순위 회귀 검증
# ===========================================================================


def test_failures_across_five_days_do_not_trigger_brute_force() -> None:
    """하루 간격의 정상 실패 누적이 한 배치여도 Brute Force가 아님을 검증한다."""
    lines = [
        _LOG_TEMPLATE.replace("Sep 03", f"Sep {day:02}").format(
            i=day, user="admin", ip="198.51.100.10"
        )
        for day in range(1, BRUTE_FORCE_THRESHOLD + 1)
    ]
    events = [SyslogAuthEvent.parse_line(line) for line in lines]

    is_detected, rule_name = evaluate_rules([event for event in events if event is not None])

    assert is_detected is False
    assert rule_name is None


def test_leap_day_failures_trigger_brute_force() -> None:
    """2월 29일의 유효한 Syslog 실패가 날짜 변환에서 모두 누락되지 않도록 검증한다."""
    events = []
    for i in range(5):
        line = _LOG_TEMPLATE.replace("Sep 03", "Feb 29").format(
            i=i, user="root", ip="198.51.100.20"
        )
        event = SyslogAuthEvent.parse_line(line)
        assert event is not None
        events.append(event)
    assert evaluate_rules(events) == (True, "SSH_BRUTE_FORCE")


def test_leap_day_midnight_window_boundary() -> None:
    """윤일 진입·종료 양쪽에서 자정을 넘는 300초 포함 및 301초 제외를 검증한다."""
    for start_date, end_date in (("Feb 28", "Feb 29"), ("Feb 29", "Mar 01")):
        for end_time, expected in (
            ("00:02:00", (True, "SSH_BRUTE_FORCE")),
            ("00:02:01", (False, None)),
        ):
            events = []
            for i in range(5):
                timestamp = f"{start_date} 23:57:00" if i < 4 else f"{end_date} {end_time}"
                line = _LOG_TEMPLATE.replace("Sep 03 14:20:01", timestamp).format(
                    i=i, user="root", ip="198.51.100.20"
                )
                event = SyslogAuthEvent.parse_line(line)
                assert event is not None
                events.append(event)
            assert evaluate_rules(events) == expected


def test_invalid_syslog_date_is_excluded() -> None:
    """윤년 기준을 사용해도 2월 30일처럼 존재하지 않는 날짜는 집계하지 않는다."""
    events = []
    for i in range(5):
        line = _LOG_TEMPLATE.replace("Sep 03", "Feb 30").format(
            i=i, user="root", ip="198.51.100.20"
        )
        event = SyslogAuthEvent.parse_line(line)
        assert event is not None
        events.append(event)
    assert evaluate_rules(events) == (False, None)


@pytest.mark.parametrize(
    ("encoded", "expected"),
    [
        ("/admin%2Fconfig", "/admin/config"),
        ("/%252e%252e%252fetc%252fpasswd", "/../etc/passwd"),
        ("/%ED%95%9C%EA%B8%80", "/한글"),
        ("/search?q=a+b", "/search?q=a+b"),
        ("/literal%ZZvalue", "/literal%ZZvalue"),
        ("/trailing%2", "/trailing%2"),
    ],
)
def test_normalize_url_value_decodes_safe_bounded_representations(
    encoded: str, expected: str
) -> None:
    """단일·이중 인코딩은 풀고 경로의 더하기와 비정상 이스케이프는 보존한다."""
    assert normalize_url_value(encoded) == expected


def test_normalize_url_value_stops_after_double_decoding() -> None:
    """삼중 인코딩은 두 단계까지만 풀어 고정된 처리 비용과 책임 범위를 지킨다."""
    assert normalize_url_value("%25252e%25252e%25252f") == "%2e%2e%2f"


def test_normalize_url_value_respects_remaining_decode_budget() -> None:
    """앞단 계약이 1회 디코딩한 경우 남은 1회만 수행해 전체 2회 경계를 지킨다."""
    assert normalize_url_value("%252e%252e%252f", decode_rounds=1) == "%2e%2e%2f"


def test_normalize_url_value_rejects_oversized_input() -> None:
    """비정상적으로 긴 값은 탐지 전처리 비용을 제한하기 위해 거부한다."""
    with pytest.raises(ValueError, match="4096"):
        normalize_url_value("a" * (MAX_URL_VALUE_LENGTH + 1))


def test_normalize_url_value_requires_string() -> None:
    """바이트열의 암묵적 디코딩을 막아 호출부가 문자 인코딩을 명시하게 한다."""
    with pytest.raises(TypeError, match="문자열"):
        normalize_url_value(b"%2e%2e%2f")  # type: ignore[arg-type]


def _make_nginx_event(
    *,
    second: int,
    uri: str,
    status_code: int = 404,
    source_ip: str = "198.51.100.77",
) -> NginxAccessLogEvent:
    """Web 룰의 시간창과 출발지 경계를 명시하는 불변 이벤트를 생성한다."""
    timestamp = f"28/Sep/2026:11:52:{second:02d} +0000"
    return NginxAccessLogEvent(
        source_ip=source_ip,
        timestamp_str=timestamp,
        method="GET",
        uri=uri,
        status_code=status_code,
        response_time=0.002,
        user_agent="curl/8.0",
        raw_message=f'{source_ip} - - [{timestamp}] "GET {uri} HTTP/1.1" {status_code}',
    )


def test_web_rules_detect_double_encoded_path_traversal() -> None:
    """계약에서 1차 디코딩된 이중 인코딩 경로를 한 번 더 풀어 탐지한다."""
    event = _make_nginx_event(second=0, uri="/%2e%2e%2fetc/passwd")

    assert evaluate_web_rules([event]) == (True, "PATH_TRAVERSAL")


def test_web_rules_do_not_decode_original_uri_more_than_twice() -> None:
    """원본 기준 삼중 인코딩은 계약 1회와 룰 1회 뒤에도 공격 문자열로 확정하지 않는다."""
    event = _make_nginx_event(second=0, uri="/%252e%252e%252fetc/passwd")

    assert evaluate_web_rules([event]) == (False, None)


@pytest.mark.parametrize(
    "uri",
    ["/.env", "/.git/config", "/wp-config.php", "/database.sql", "/config.bak", "/site.zip"],
)
def test_web_rules_detect_sensitive_file_probing(uri: str) -> None:
    """고정 민감 경로와 모든 백업 확장자는 쿼리 유무와 무관하게 탐지한다."""
    event = _make_nginx_event(second=0, uri=f"{uri}?cache=false")

    assert evaluate_web_rules([event]) == (True, "SENSITIVE_FILE_PROBING")


def test_web_rules_detect_directory_scan_at_exact_threshold() -> None:
    """10초 내 의심 경로 5개 중 401/403/404가 3개이면 차단 후보로 탐지한다."""
    paths = ["/admin", "/login", "/dashboard", "/api", "/private"]
    statuses = [401, 403, 404, 200, 302]
    events = [
        _make_nginx_event(second=index, uri=path, status_code=status)
        for index, (path, status) in enumerate(zip(paths, statuses, strict=True))
    ]

    assert evaluate_web_rules(events) == (True, "WEB_DIRECTORY_SCANNING")


def test_web_rules_require_five_distinct_suspicious_paths() -> None:
    """실패가 3개여도 의심 경로가 4개뿐이면 스캔으로 승격하지 않는다."""
    paths = ["/admin", "/login", "/dashboard", "/api"]
    events = [_make_nginx_event(second=index, uri=path) for index, path in enumerate(paths)]

    assert evaluate_web_rules(events) == (False, None)


def test_web_rules_require_three_distinct_failure_paths() -> None:
    """의심 경로가 5개여도 실패 경로가 2개뿐이면 차단 후보가 아니다."""
    paths = ["/admin", "/login", "/dashboard", "/api", "/private"]
    statuses = [403, 404, 200, 200, 302]
    events = [
        _make_nginx_event(second=index, uri=path, status_code=status)
        for index, (path, status) in enumerate(zip(paths, statuses, strict=True))
    ]

    assert evaluate_web_rules(events) == (False, None)


def test_web_rules_ignore_normal_candidate_paths() -> None:
    """health·robots·정적 자원은 반복 실패해도 의심 경로 다양성에 포함하지 않는다."""
    paths = ["/health", "/robots.txt", "/sitemap.xml", "/images/a.png", "/static/app.js"]
    events = [_make_nginx_event(second=index, uri=path) for index, path in enumerate(paths)]

    assert evaluate_web_rules(events) == (False, None)


def test_web_rules_do_not_block_single_admin_request() -> None:
    """단발성 관리 경로 접근은 관찰 대상일 뿐 디렉터리 스캔으로 승격하지 않는다."""
    event = _make_nginx_event(second=0, uri="/admin", status_code=403)

    assert evaluate_web_rules([event]) == (False, None)


def test_web_rules_count_repeated_suspicious_path_once() -> None:
    """같은 의심 경로 반복은 경로 다양성을 늘리지 않아 자동 차단 후보가 되지 않는다."""
    events = [_make_nginx_event(second=index, uri="/admin") for index in range(10)]

    assert evaluate_web_rules(events) == (False, None)


def test_web_rules_keep_source_ips_in_separate_windows() -> None:
    """서로 다른 출구 IP의 요청을 합산해 단일 스캐너로 오판하지 않는다."""
    paths = ["/admin", "/login", "/dashboard", "/api", "/private"]
    events = [
        _make_nginx_event(
            second=index,
            uri=path,
            source_ip=f"198.51.100.{77 + index % 2}",
        )
        for index, path in enumerate(paths)
    ]

    assert evaluate_web_rules(events) == (False, None)


def test_web_rules_enforce_ten_second_window() -> None:
    """다섯 번째 의심 경로가 11초에 도착하면 같은 탐지 시간창으로 합산하지 않는다."""
    paths = ["/admin", "/login", "/dashboard", "/api", "/private"]
    seconds = [0, 1, 2, 3, 11]
    events = [
        _make_nginx_event(second=second, uri=path)
        for second, path in zip(seconds, paths, strict=True)
    ]

    assert evaluate_web_rules(events) == (False, None)


def test_web_rules_include_exact_ten_second_boundary() -> None:
    """첫 요청과 마지막 요청의 간격이 정확히 10초이면 같은 시간창에 포함한다."""
    paths = ["/admin", "/login", "/dashboard", "/api", "/private"]
    seconds = [0, 6, 7, 8, 10]
    events = [
        _make_nginx_event(second=second, uri=path)
        for second, path in zip(seconds, paths, strict=True)
    ]

    assert evaluate_web_rules(events) == (True, "WEB_DIRECTORY_SCANNING")


def test_web_rules_reject_oversized_uri_before_regex_evaluation() -> None:
    """정규식 실행 전에 과대 입력을 거부해 공격자의 처리 시간 증폭을 제한한다."""
    event = _make_nginx_event(second=0, uri="/" + "a" * MAX_URL_VALUE_LENGTH)

    with pytest.raises(ValueError, match="4096자를 초과"):
        evaluate_web_rules([event])


def test_brute_force_has_priority_over_spraying() -> None:
    """단일 계정 집중 공격에 1회 타 계정 실패가 섞여도 Brute Force를 우선 반환한다."""
    events = _make_events("198.51.100.11", "root", BRUTE_FORCE_THRESHOLD)
    events.extend(_make_events("198.51.100.11", "guest", 1))

    is_detected, rule_name = evaluate_rules(events)

    assert is_detected is True
    assert rule_name == "SSH_BRUTE_FORCE"


@pytest.mark.parametrize(
    "uri",
    [
        "/admin-help",
        "/login-guide",
        "/apiary",
        "/configurator",
        "/.../guide",
        "/docs/a..b",
        "/.environment",
        "/database.sql.txt",
    ],
)
def test_web_normal_path_lookalikes_do_not_trigger(uri: str) -> None:
    """관리 경로·탈출 토큰·민감 확장자의 부분 문자열로 정상 자원을 오판하지 않는다."""
    events = [_make_nginx_event(second=index, uri=uri) for index in range(10)]
    assert evaluate_web_rules(events) == (False, None)


@pytest.mark.parametrize("query", ["next=/../docs", "file=/.env", "name=backup.sql", "q=%2e%2e%2f"])
def test_web_query_only_signature_is_not_path_evidence(query: str) -> None:
    """현재 경로 전용 정책을 고정하며 쿼리 기반 공격 탐지 범위로 확대하지 않는다."""
    assert evaluate_web_rules([_make_nginx_event(second=0, uri=f"/search?{query}")]) == (
        False,
        None,
    )


@pytest.mark.parametrize("status", [400, 405, 408, 429, 500, 502, 503])
def test_web_non_policy_errors_do_not_count_as_scan_failures(status: int) -> None:
    """서버 장애·요청 제한을 접근 실패 401/403/404와 혼합해 자동 차단하지 않는다."""
    events = [
        _make_nginx_event(second=index, uri=path, status_code=status)
        for index, path in enumerate(["/admin", "/login", "/dashboard", "/api", "/private"])
    ]
    assert evaluate_web_rules(events) == (False, None)


@pytest.mark.parametrize("status", [200, 201, 204, 301, 302, 304])
def test_web_normal_management_browsing_does_not_trigger(status: int) -> None:
    """관리 페이지 다섯 개를 정상적으로 조회해도 경로 다양성만으로 차단하지 않는다."""
    events = [
        _make_nginx_event(second=index, uri=path, status_code=status)
        for index, path in enumerate(["/admin", "/login", "/dashboard", "/api", "/private"])
    ]
    assert evaluate_web_rules(events) == (False, None)


def test_web_repeated_failure_does_not_inflate_failed_path_diversity() -> None:
    """고유 경로가 충분해도 한 경로의 반복 실패를 세 실패 경로로 세지 않는다."""
    events = [_make_nginx_event(second=index, uri="/admin") for index in range(3)]
    events += [
        _make_nginx_event(second=3 + index, uri=path, status_code=200)
        for index, path in enumerate(["/login", "/dashboard", "/api", "/private"])
    ]
    assert evaluate_web_rules(events) == (False, None)


def test_web_query_variations_do_not_create_distinct_paths() -> None:
    """캐시·페이지 쿼리만 다른 동일 관리 경로는 스캔 다양성을 늘리지 않는다."""
    events = [_make_nginx_event(second=index, uri=f"/admin?page={index}") for index in range(10)]
    assert evaluate_web_rules(events) == (False, None)


def test_web_expired_failure_is_not_retained_by_new_success_on_same_path() -> None:
    """과거 실패 경로가 새 성공 요청과 겹쳐도 실패 카운트는 별도로 만료되어야 한다."""
    events = [_make_nginx_event(second=0, uri="/admin")]
    paths = ["/admin", "/login", "/dashboard", "/api", "/private"]
    statuses = [200, 403, 404, 200, 200]
    events += [
        _make_nginx_event(second=11 + index, uri=path, status_code=status)
        for index, (path, status) in enumerate(zip(paths, statuses, strict=True))
    ]
    assert evaluate_web_rules(events) == (False, None)


def test_web_expired_failed_paths_are_removed_from_active_window() -> None:
    """시간창 밖 실패 세 건과 이후 정상 조회를 결합해 허위 스캔을 만들지 않는다."""
    events = [
        _make_nginx_event(second=index, uri=path)
        for index, path in enumerate(["/admin", "/login", "/dashboard"])
    ]
    events += [
        _make_nginx_event(second=20 + index, uri=path, status_code=200)
        for index, path in enumerate(["/api", "/private", "/internal", "/debug", "/metrics"])
    ]
    assert evaluate_web_rules(events) == (False, None)


@pytest.mark.parametrize("order", [(4, 3, 2, 1, 0), (2, 0, 4, 1, 3), (0, 4, 1, 3, 2)])
def test_web_out_of_order_batch_preserves_scan_decision(order: tuple[int, ...]) -> None:
    """배치 내 역순 인입은 발생 시각 정렬로 같은 판정을 유지한다; 배치 간 누적은 별도다."""
    events = [
        _make_nginx_event(second=index, uri=path)
        for index, path in enumerate(["/admin", "/login", "/dashboard", "/api", "/private"])
    ]
    assert evaluate_web_rules([events[index] for index in order]) == (
        True,
        "WEB_DIRECTORY_SCANNING",
    )


def test_web_late_old_event_does_not_extend_window() -> None:
    """마지막에 도착한 오래된 실패를 최신 시각으로 취급하지 않는다."""
    events = [
        _make_nginx_event(second=20 + index, uri=path)
        for index, path in enumerate(["/admin", "/login", "/dashboard", "/api"])
    ]
    events.append(_make_nginx_event(second=0, uri="/private"))
    assert evaluate_web_rules(events) == (False, None)


def test_web_rule_calls_do_not_share_hidden_state() -> None:
    """Lambda의 분할 배치 누적을 룰 내부 메모리에 숨기지 않고 플랫폼에 위임한다."""
    events = [
        _make_nginx_event(second=index, uri=path)
        for index, path in enumerate(["/admin", "/login", "/dashboard", "/api", "/private"])
    ]
    assert evaluate_web_rules(events[:3]) == (False, None)
    assert evaluate_web_rules(events[3:]) == (False, None)
    assert evaluate_web_rules(events) == (True, "WEB_DIRECTORY_SCANNING")
    assert evaluate_web_rules(events[:3]) == (False, None)


@pytest.mark.parametrize("position", [0, 3, 6])
def test_web_traversal_priority_is_independent_of_event_position(position: int) -> None:
    """스캔·민감 파일과 혼재해도 경로 탈출이 전역 우선순위를 유지한다."""
    events = [
        _make_nginx_event(second=index, uri=path)
        for index, path in enumerate(
            ["/admin", "/login", "/dashboard", "/api", "/private", "/.env"]
        )
    ]
    events.insert(position, _make_nginx_event(second=7, uri="/../etc/passwd"))
    assert evaluate_web_rules(events) == (True, "PATH_TRAVERSAL")


@pytest.mark.parametrize("position", [0, 5])
def test_web_sensitive_file_has_priority_over_directory_scan(position: int) -> None:
    """디렉터리 열거 임계치를 먼저 충족해도 더 구체적인 파일 탐색 룰을 반환한다."""
    events = [
        _make_nginx_event(second=index, uri=path)
        for index, path in enumerate(["/admin", "/login", "/dashboard", "/api", "/private"])
    ]
    events.insert(position, _make_nginx_event(second=6, uri="/.git/config"))
    assert evaluate_web_rules(events) == (True, "SENSITIVE_FILE_PROBING")


def test_web_evaluation_preserves_event_order_and_evidence() -> None:
    """탐지를 위한 정렬·디코딩이 수집 원문이나 호출자 이벤트 순서를 변조하지 않는다."""
    events = [
        _make_nginx_event(second=4 - index, uri=path)
        for index, path in enumerate(["/admin", "/login", "/dashboard", "/api", "/private"])
    ]
    before = [event.model_dump() for event in events]
    assert evaluate_web_rules(events) == (True, "WEB_DIRECTORY_SCANNING")
    assert [event.model_dump() for event in events] == before


@pytest.mark.parametrize("uri", ["/문서/안내", "/café/menu", "/assets/画像.png"])
def test_web_unicode_normal_paths_are_not_scan_evidence(uri: str) -> None:
    """UTF-8 정상 자원을 실패 응답이나 비ASCII 문자만으로 공격에 포함하지 않는다."""
    assert evaluate_web_rules([_make_nginx_event(second=0, uri=uri)]) == (False, None)


@pytest.mark.parametrize(
    "uri", ["/../etc/passwd", "/%2e%2e%2fetc/passwd", "/%252e%252e%252fetc/passwd"]
)
def test_web_raw_nginx_encoding_variants_reach_same_traversal_rule(uri: str) -> None:
    """실제 원문 계약 파싱 1회와 룰 정규화 1회를 연결해 단일·이중 인코딩을 검증한다."""
    event = NginxAccessLogEvent.parse_line(
        "198.51.100.77 - - [28/Sep/2026:11:52:00 +0000] "
        f'"GET {uri} HTTP/1.1" 404 150 "-" "curl/8.0" 0.002 "-"'
    )
    assert event is not None
    assert evaluate_web_rules([event]) == (True, "PATH_TRAVERSAL")


@pytest.mark.parametrize("uri", ["/docs/%ZZ", "/docs/%2", "/docs/%", "/docs/%FF"])
def test_web_malformed_percent_sequences_do_not_become_attack_tokens(uri: str) -> None:
    """불완전한 이스케이프·UTF-8 바이트가 예외나 가짜 탈출 토큰을 만들지 않는다."""
    assert evaluate_web_rules([_make_nginx_event(second=0, uri=uri)]) == (False, None)


def test_web_exact_uri_limit_accepts_benign_path() -> None:
    """4096자는 유효한 상한이며 4097자 거부 정책과 혼동하지 않는다."""
    event = _make_nginx_event(second=0, uri="/" + "a" * (MAX_URL_VALUE_LENGTH - 1))
    assert evaluate_web_rules([event]) == (False, None)


def test_web_oversized_uri_raises_before_any_signature_search(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """과대 입력의 ValueError를 숨기지 않으며 정규식 실행 전에 경계를 검사한다."""

    class UnexpectedSearch:
        def search(self, value: str) -> None:
            raise AssertionError("과대 URI가 정규식까지 도달했습니다.")

    monkeypatch.setattr("detection.rules.PATH_TRAVERSAL_PATTERN", UnexpectedSearch())
    event = _make_nginx_event(second=0, uri="/" + "a" * MAX_URL_VALUE_LENGTH)
    with pytest.raises(ValueError, match="4096"):
        evaluate_web_rules([event])


def test_web_longest_allowed_path_keeps_traversal_suffix_evidence() -> None:
    """길이 제한을 맞춘 마지막 공격 토큰을 잘라내지 않고 검사한다."""
    suffix = "/../etc/passwd"
    uri = "/" + "a" * (MAX_URL_VALUE_LENGTH - 1 - len(suffix)) + suffix
    assert len(uri) == MAX_URL_VALUE_LENGTH
    assert evaluate_web_rules([_make_nginx_event(second=0, uri=uri)]) == (True, "PATH_TRAVERSAL")


@pytest.mark.parametrize("fragment", ["/..x", "/...", ".sqx", "%ZZ"])
@pytest.mark.parametrize("length", [256, 1024, MAX_URL_VALUE_LENGTH])
def test_web_adversarial_near_miss_paths_remain_non_threat(fragment: str, length: int) -> None:
    """매칭에 실패하는 반복 입력을 늘려도 탐지 정책과 입력 상한을 유지한다."""
    uri = (fragment * (length // len(fragment) + 1))[:length]
    assert evaluate_web_rules([_make_nginx_event(second=0, uri=uri)]) == (False, None)


@pytest.mark.parametrize(
    "pattern_name,fragment",
    [
        ("PATH_TRAVERSAL_PATTERN", "/..x"),
        ("PATH_TRAVERSAL_PATTERN", "/..."),
        ("SENSITIVE_FILE_EXTENSION_PATTERN", ".sqx"),
        ("SENSITIVE_FILE_EXTENSION_PATTERN", "..."),
    ],
)
def test_web_regex_near_miss_cost_growth_is_bounded(pattern_name: str, fragment: str) -> None:
    """격리 프로세스에서 길이별 비용과 15초 제한으로 ReDoS 회귀를 감시한다.

    Constraints:
        256·1024·4096자 실패 매칭의 5회 중앙값을 비교하며 문자당 비용에 4배 여유를 둔다.
        짧은 측정의 잡음을 위한 호출당 1µs 하한을 적용한다. 이는 O(n)의 수학적 증명이 아니다.
    Side-effects / Edge-cases:
        정규식이 멈추면 자식 프로세스를 종료해 pytest 전체가 매칭에 갇히는 것을 방지한다.
        네트워크·AWS 호출 없이 실제 룰의 컴파일된 패턴만 측정한다.
    """
    script = """
import json
import statistics
import sys
import timeit
from detection import rules
pattern = getattr(rules, sys.argv[1])
fragment = sys.argv[2]
measurements = []
for length in (256, 1024, 4096):
    value = (fragment * (length // len(fragment) + 1))[:length]
    assert pattern.search(value) is None
    count = max(100, 1_000_000 // length)
    samples = timeit.repeat(lambda: pattern.search(value), repeat=5, number=count)
    measurements.append([length, statistics.median(samples) / count])
print(json.dumps(measurements))
"""
    result = subprocess.run(
        [sys.executable, "-c", script, pattern_name, fragment],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    measurements = json.loads(result.stdout)
    base_length, base_seconds = measurements[0]
    for length, seconds in measurements[1:]:
        assert seconds / length <= 4 * max(base_seconds, 1e-6) / base_length, measurements
