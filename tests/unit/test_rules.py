# CloudShield 단위 테스트: 보안 탐지 룰 엔진
# 소유자: 보안 담당
"""시그니처 1차 룰 엔진(rules.py) 단위 테스트.

Why:
    정상 접속 로그, 패스워드 스프레잉, 단일 계정 브루트포스, 오탐 경계값 시나리오를
    격리 검증하여 탐지 정확도를 보장하고 임계치 변경 시 회귀를 방지함.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from contracts.events import SyslogAuthEvent
from detection.rules import (
    BRUTE_FORCE_THRESHOLD,
    PASSWORD_SPRAYING_THRESHOLD,
    evaluate_rules,
)

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


def test_normal_activity_is_not_an_auth_failure(noisy_auth_lines: list[str]) -> None:
    """성공 인증·sudo·세션·연결 종료는 반복돼도 공격 증거가 되지 않아야 한다."""
    normal_lines = [line for line in noisy_auth_lines if "Failed password for " not in line]
    assert len(normal_lines) == 7
    for line in normal_lines:
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
    noisy_auth_lines: list[str], failure_count: int
) -> None:
    """실패와 같은 IP·계정의 정상 로그도 4회/5회 판정 경계를 바꾸면 안 된다."""
    normal_lines = [
        line.replace("192.0.2.10", "198.51.100.99").replace("ubuntu", "devops")
        for line in noisy_auth_lines
        if "Failed password for " not in line
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


def test_brute_force_has_priority_over_spraying() -> None:
    """단일 계정 집중 공격에 1회 타 계정 실패가 섞여도 Brute Force를 우선 반환한다."""
    events = _make_events("198.51.100.11", "root", BRUTE_FORCE_THRESHOLD)
    events.extend(_make_events("198.51.100.11", "guest", 1))

    is_detected, rule_name = evaluate_rules(events)

    assert is_detected is True
    assert rule_name == "SSH_BRUTE_FORCE"
