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
    - 입력 로그는 SyslogAuthEvent 리스트 형태여야 함.
"""

from __future__ import annotations

from contracts.events import SyslogAuthEvent

# 타입 호환성 및 개발 편의성을 위한 별칭 제공
SyslogEvent = SyslogAuthEvent


def evaluate_rules(logs: list[SyslogAuthEvent]) -> tuple[bool, str | None]:
    """수집된 Syslog 인증 이벤트 목록을 분석하여 위협 여부 및 탐지 룰 식별.

    Why:
        동일 출발지 IP 기반의 단시간 실패 임계치(단일 계정 5회 이상, 다중 계정 2개 이상)를
        평가하여 신속한 인프라 선제 차단(HIGH) 여부를 결정함.

    Constraints:
        - logs: 비어 있지 않은 SyslogAuthEvent(또는 SyslogEvent) 인스턴스 리스트.
        - 반환값: (위협_탐지_여부: bool, 매칭된_규칙명_또는_None: str | None).

    Side-effects / Edge-cases:
        - 빈 리스트 인입 시 (False, None)을 반환해야 함.
        - 정상 로그인 실패(1~2회 단순 오타)는 오탐(False Positive) 방지를 위해 탐지하지 않음.
        - 단일 IP에서 서로 다른 사용자 계정으로 실패가 누적될 경우
          Password Spraying(T1110.003)으로 분류.
    """
    raise NotImplementedError("보안 담당자 구현 영역: 시그니처 기반 1차 룰 엔진")
