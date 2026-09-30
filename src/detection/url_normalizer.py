# CloudShield 탐지 엔진: Web URL 정규화 전처리
# 소유자: 보안 담당
"""URL 퍼센트 인코딩 우회를 탐지 가능한 표준 문자열로 정규화한다.

Why:
    공격자는 ``../`` 같은 Web 공격 문자열을 단일 또는 이중 퍼센트 인코딩해
    원문 기반 시그니처를 우회할 수 있다. 탐지 전에 표현을 통일해 동일한 룰로 판정한다.

Constraints:
    - 이 티켓의 공격 모델에 맞춰 최대 2회까지만 디코딩한다.
    - 과도한 입력으로 인한 처리 비용을 제한하기 위해 최대 4096자를 허용한다.
    - ``+``는 URL 경로에서 유효한 문자이므로 공백으로 변환하지 않는다.

Side-effects / Edge-cases:
    - 잘못된 ``%`` 이스케이프는 urllib 표준 동작에 따라 원문 그대로 유지된다.
    - 경로 결합이나 ``..`` 제거는 수행하지 않아 공격 증거가 탐지 룰에 보존된다.
"""

from __future__ import annotations

from urllib.parse import unquote

MAX_URL_VALUE_LENGTH = 4096
MAX_DECODE_ROUNDS = 2


def normalize_url_value(value: str, *, decode_rounds: int = MAX_DECODE_ROUNDS) -> str:
    """단일·이중 퍼센트 인코딩 URL 값을 탐지용 문자열로 정규화한다.

    Args:
        value: Nginx 요청 경로 등에서 추출한 URL 문자열.
        decode_rounds: 이 호출에서 허용할 디코딩 횟수. 앞단 계약이 이미 한 번
            디코딩한 경우 1을 전달해 원본 기준 최대 2회 경계를 유지한다.

    Returns:
        최대 두 번 퍼센트 디코딩한 문자열. 추가 변환이 없으면 즉시 반환한다.

    Raises:
        TypeError: 입력이 문자열이 아닌 경우.
        ValueError: 입력 길이가 4096자를 초과하거나 디코딩 횟수가 범위를 벗어난 경우.
    """
    if not isinstance(value, str):
        raise TypeError("URL 정규화 입력은 문자열이어야 합니다.")
    if len(value) > MAX_URL_VALUE_LENGTH:
        raise ValueError(f"URL 정규화 입력은 {MAX_URL_VALUE_LENGTH}자를 초과할 수 없습니다.")
    if not isinstance(decode_rounds, int) or not 0 <= decode_rounds <= MAX_DECODE_ROUNDS:
        raise ValueError(f"URL 디코딩 횟수는 0~{MAX_DECODE_ROUNDS} 범위여야 합니다.")

    normalized = value
    for _ in range(decode_rounds):
        decoded = unquote(normalized, encoding="utf-8", errors="replace")
        if decoded == normalized:
            break
        normalized = decoded
    return normalized
