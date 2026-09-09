# CloudShield 탐지 엔진: 1차 시그니처 룰
# 소유자: 보안 담당
"""시그니처 기반 1차 위협 탐지 룰 엔진.

Why:
    CloudWatch Logs를 통해 실시간 인입되는 Syslog 이벤트 스트림에서
    무차별 대입(Brute Force) 및 패스워드 스프레잉(Password Spraying) 공격을
    결정론적(Deterministic) 정규식과 임계치 기반으로 1차 필터링하여
    고비용 LLM API 호출을 최적화하고 초동 대응 골든타임을 확보함.

Constraints:
    - ReDoS(Catastrophic Backtracking) 방어를 위해 정규식 패턴은 단순 선형 탐색을 유지함.
      역참조(Backreference) 및 중첩 반복 수량자(Nested Quantifier) 사용 금지.
    - 입력 로그는 SyslogAuthEvent 리스트 형태여야 함.
    - 룰명(rule_name)은 Lambda 오케스트레이터 및 Slack 알림 카드의 식별 키로 사용되므로
      SCREAMING_SNAKE_CASE 컨벤션을 반드시 준수함 (예: SSH_BRUTE_FORCE).

MITRE ATT&CK 매핑:
    - SSH_BRUTE_FORCE        → T1110.001 (Brute Force: Password Guessing)
    - SSH_PASSWORD_SPRAYING  → T1110.003 (Brute Force: Password Spraying)
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from contracts.events import SyslogAuthEvent

# 타입 호환성 및 개발 편의성을 위한 별칭 제공
SyslogEvent = SyslogAuthEvent

# ---------------------------------------------------------------------------
# 탐지 임계치 상수
# ---------------------------------------------------------------------------

# 단일 계정 대상 실패 횟수 임계치 (T1110.001 Brute Force: Password Guessing)
# Why: Hydra 기본 설정 및 실제 침해 사례 분석 결과, 5회 이상을 자동화 공격으로 판정.
#      1~4회는 정상 관리자 오타 범주로 허용하여 오탐을 억제함.
BRUTE_FORCE_THRESHOLD: int = 5

# 다중 계정 대상 고유 계정 수 임계치 (T1110.003 Password Spraying)
# Why: 동일 IP에서 2개 이상의 계정을 시도하면 계정 목록 보유 공격자로 판정.
#      스프레잉은 단일 계정 실패 횟수와 무관하게 계정 다양성으로 판별함.
PASSWORD_SPRAYING_THRESHOLD: int = 2

# 반복 실패 탐지 시간창(초)
# Why: 서로 다른 날짜에 발생한 정상 로그인 오류를 한 배치로 수신했다는 이유만으로
#      자동화 공격으로 오판하지 않도록, 공격의 시간적 밀집도를 필수 조건으로 둠.
# Constraints: CloudWatch Subscription Filter의 전송 지연을 고려한 5분(300초) 고정 창.
DETECTION_WINDOW_SECONDS: int = 5 * 60

def _timestamp_to_epoch_seconds(timestamp_str: str) -> float | None:
    """계약의 Syslog/ISO 8601 시각을 비교 가능한 초 단위 값으로 정규화한다.

    Syslog에는 연도가 없으므로 윤년 영향이 없는 기준 연도 2001을 사용한다. 이 값은
    절대 시각이 아닌 동일 로그 배치 안의 시간 간격 판정에만 사용한다.
    """
    try:
        if "T" in timestamp_str:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()
        return datetime.strptime(f"2001 {timestamp_str}", "%Y %b %d %H:%M:%S").timestamp()
    except ValueError:
        # 계약 밖의 시각 포맷은 시간 기반 집계에서 제외해 오래된 이벤트의 오탐을 방지한다.
        return None


def _has_repeated_events_within_window(timestamps: list[float], threshold: int) -> bool:
    """정렬된 시각 목록에 임계치 이상의 이벤트가 시간창 내 밀집했는지 판정한다."""
    timestamps.sort()
    left = 0
    for right, timestamp in enumerate(timestamps):
        while timestamp - timestamps[left] > DETECTION_WINDOW_SECONDS:
            left += 1
        if right - left + 1 >= threshold:
            return True
    return False


def evaluate_rules(logs: list[SyslogAuthEvent]) -> tuple[bool, str | None]:
    """Syslog SSH 인증 실패 이벤트 리스트에 1차 시그니처 룰을 적용한다.

    적용 룰 (우선순위 순):
        1. SSH_BRUTE_FORCE       : 동일 IPㆍ계정에서 5분 내 5회 이상 실패.
        2. SSH_PASSWORD_SPRAYING : 동일 IP에서 5분 내 2개 이상 고유 계정 실패.

    Args:
        logs: SyslogAuthEvent 파싱 완료 이벤트 리스트.

    Returns:
        (탐지 여부: bool, 룰명: str | None) 튜플.
        탐지 없을 경우 (False, None) 반환.

    Side-effects / Edge-cases:
        - 빈 리스트 입력 시 즉시 (False, None) 반환.
        - 동일 이벤트가 복수 룰에 해당하는 경우 우선순위가 높은 룰 하나만 반환.
          (중복 알림으로 인한 Slack 노이즈 방지)
    """
    if not logs:
        return False, None

    # IP → (발생 시각, 계정명, 원문) 목록. 시간창 밖 이벤트는 같은 배치여도 합산하지 않는다.
    ip_events: dict[str, list[tuple[float, str, str]]] = defaultdict(list)

    for event in logs:
        timestamp = _timestamp_to_epoch_seconds(event.timestamp_str)
        if timestamp is not None:
            ip_events[event.source_ip].append((timestamp, event.username, event.raw_message))

    # 룰 1: 구체적이고 높은 위험도의 단일 계정 집중 공격을 전역적으로 먼저 평가한다.
    for events in ip_events.values():
        account_timestamps: dict[str, list[float]] = defaultdict(list)
        for timestamp, username, _ in events:
            account_timestamps[username].append(timestamp)
        if any(
            _has_repeated_events_within_window(timestamps, BRUTE_FORCE_THRESHOLD)
            for timestamps in account_timestamps.values()
        ):
            return True, "SSH_BRUTE_FORCE"

    # 룰 2: 한 시간창에서만 서로 다른 계정 수를 계산한다.
    for events in ip_events.values():
        events.sort(key=lambda event: event[0])
        account_counts: dict[str, int] = defaultdict(int)
        left = 0
        for _, (timestamp, username, _) in enumerate(events):
            account_counts[username] += 1
            while timestamp - events[left][0] > DETECTION_WINDOW_SECONDS:
                expired_username = events[left][1]
                account_counts[expired_username] -= 1
                if account_counts[expired_username] == 0:
                    del account_counts[expired_username]
                left += 1
            if len(account_counts) >= PASSWORD_SPRAYING_THRESHOLD:
                return True, "SSH_PASSWORD_SPRAYING"

    return False, None
