"""FilterLogEvents 원본을 분석한다. API 조회 시각은 수집 시각으로 사용하지 않는다."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

MAX_EVENTS = 100_000
MAX_INPUT_BYTES = 32 * 1024 * 1024


def summarize_collection_latency(
    events: list[dict[str, Any]], *, expected_count: int, budget_ms: int = 3000
) -> dict[str, Any]:
    """이벤트별 ingestionTime - timestamp를 ms 단위로 집계한다.

    Why: 역순 도착과 재조회 중복으로 지연 통계가 왜곡되는 것을 방지한다.
    Constraints: 양의 기대 건수/예산, 최대 10만 건. ID는 한 로그 그룹 내에서 비교한다.
    Side-effects: 외부 호출 및 영속 상태 없음. 누락 필드, 시계 역전, 충돌 중복은 예외 전파.
    """
    for name, value in (("expected_count", expected_count), ("budget_ms", budget_ms)):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
    if not isinstance(events, list) or not events or len(events) > MAX_EVENTS:
        raise ValueError("events must contain 1..100000 entries")
    seen: dict[str, tuple[int, int]] = {}
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("event must be an object")
        event_id = event.get("eventId")
        timestamp, ingestion = event.get("timestamp"), event.get("ingestionTime")
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("eventId is required")
        if any(type(v) is not int or v < 0 for v in (timestamp, ingestion)):
            raise ValueError("timestamps must be non-negative integer milliseconds")
        if ingestion < timestamp:
            raise ValueError("negative latency: check clock synchronization")
        pair = (timestamp, ingestion)
        if event_id in seen and seen[event_id] != pair:
            raise ValueError("conflicting duplicate eventId")
        seen[event_id] = pair
    if len(seen) > expected_count:
        raise ValueError("observed events exceed expected_count: check measurement filter")
    values = sorted(ingestion - timestamp for timestamp, ingestion in seen.values())
    complete = len(values) == expected_count
    return {
        "scope": "event_timestamp_to_cloudwatch_ingestion",
        "unit": "ms",
        "expected_count": expected_count,
        "observed_count": len(values),
        "missing_count": expected_count - len(values),
        "duplicate_count": len(events) - len(values),
        "p50_ms": values[math.ceil(len(values) * 0.50) - 1],
        "p95_ms": values[math.ceil(len(values) * 0.95) - 1],
        "max_ms": values[-1],
        "budget_ms": budget_ms,
        "over_budget_count": sum(value > budget_ms for value in values),
        "complete": complete,
        "within_budget": complete and values[-1] <= budget_ms,
    }


def main() -> None:
    """읽기 용량을 제한하고 단일 로그 그룹의 전체 페이지를 결합한 JSON을 분석한다."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--expected-count", type=int, required=True)
    parser.add_argument("--budget-ms", type=int, default=3000)
    args = parser.parse_args()
    with args.input.open("rb") as source:
        raw = source.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds 32 MiB")
    data = json.loads(raw)
    result = summarize_collection_latency(
        data["events"], expected_count=args.expected_count, budget_ms=args.budget_ms
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result["within_budget"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
