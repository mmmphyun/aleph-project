# CloudShield 상태 저장소: 배치 간 L7 웹 공격 누적 윈도우
# 소유자: 클라우드 A 담당
"""CloudWatch Logs 분할 배치 간 Nginx L7 웹 공격 이력 보존 슬라이딩 윈도우 모듈.

Why:
    CloudWatch Logs Subscription Filter는 버퍼 및 전송 정책에 따라
    짧은 간격 내 발생한 Nginx 웹 접근 로그를 여러 Lambda 배치 호출로 분할 전달함.
    무상태(Stateless)인 evaluate_web_rules는 현재 배치만 전달받을 경우
    디렉터리 스캐닝(10초 내 5개 이상 경로)과 같은 누적성 공격을 탐지하지 못하므로,
    플랫폼 런타임 영역에서 타깃/출발지 IP별 10초 이력을 호출 간 유지하고
    이벤트 ID 중복 제거 및 시간창 만료를 원자적으로 집계함.

Constraints:
    - 기본 윈도우 시간: 10초 (DEFAULT_WEB_WINDOW_SECONDS = 10.0).
    - 동일 이벤트 ID(CloudWatchLogEvent.id)는 중복 집계에서 원천 배제함.
    - 이벤트 기준 최신 타임스탬프로부터 10초를 초과한 만료 이벤트는 자동 정리됨.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from contracts.events import NginxAccessLogEvent

logger = logging.getLogger(__name__)

DEFAULT_WEB_WINDOW_SECONDS = 10.0


def parse_nginx_timestamp(timestamp_str: str) -> float | None:
    """Nginx access.log의 타임스탬프(time_local)를 epoch 초로 변환한다.

    Constraints:
        - Nginx 표준 형식: %d/%b/%Y:%H:%M:%S %z (예: 28/Sep/2026:11:52:00 +0000).
        - 형식 불일치 시 None을 반환하여 호출부가 fallback 타임스탬프를 사용하도록 함.
    """
    try:
        return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None


@dataclass
class _WebLogEntry:
    event_id: str
    timestamp_epoch: float
    event: NginxAccessLogEvent


class WebAttackWindow:
    """Nginx L7 웹 접근 로그의 호출 간 10초 슬라이딩 윈도우 관리 엔진.

    Why:
        복수의 Lambda 배치 호출로 나뉘어 전달되는 Nginx 로그를 타깃 인스턴스 및
        출발지 IP별로 누적 보존하여, 10초 시간창에 걸친 디렉터리 스캐닝 등의 위협을
        정확하게 탐지할 수 있도록 지원함.
    """

    def __init__(self, window_seconds: float = DEFAULT_WEB_WINDOW_SECONDS) -> None:
        self.window_seconds = window_seconds
        self._entries: dict[tuple[str, str], list[_WebLogEntry]] = defaultdict(list)
        self._seen_event_ids: dict[tuple[str, str], set[str]] = defaultdict(set)

    def add_event(
        self,
        target_identifier: str,
        source_ip: str,
        event_id: str,
        timestamp_epoch: float,
        event: NginxAccessLogEvent,
    ) -> bool:
        """이벤트를 윈도우에 추가한다.

        이벤트 ID가 이미 등록되어 있으면 무시하고 False를 반환한다.
        """
        key = (target_identifier, source_ip)
        if event_id in self._seen_event_ids[key]:
            return False

        self._seen_event_ids[key].add(event_id)
        self._entries[key].append(
            _WebLogEntry(
                event_id=event_id,
                timestamp_epoch=timestamp_epoch,
                event=event,
            )
        )
        return True

    def get_active_events(
        self,
        target_identifier: str,
        source_ip: str,
        reference_time: float | None = None,
    ) -> list[NginxAccessLogEvent]:
        """지정된 타깃/IP의 10초 슬라이딩 윈도우 내 유효 이벤트를 반환하고 만료 이벤트를 정리한다.

        Why:
            참조 시각(reference_time) 또는 현재 윈도우 내 최신 이벤트 시각을 기준으로
            window_seconds 이전의 만료된 이벤트를 제거하여 시간창 밖 요청의 오합산을 차단함.
        """
        key = (target_identifier, source_ip)
        entries = self._entries.get(key)
        if not entries:
            return []

        if reference_time is not None:
            ref_time = reference_time
        else:
            ref_time = max(e.timestamp_epoch for e in entries)

        cutoff = ref_time - self.window_seconds

        active_entries = [e for e in entries if cutoff <= e.timestamp_epoch <= ref_time]
        if not active_entries:
            self._entries.pop(key, None)
            self._seen_event_ids.pop(key, None)
            return []

        active_entries.sort(key=lambda e: e.timestamp_epoch)
        self._entries[key] = active_entries
        self._seen_event_ids[key] = {e.event_id for e in active_entries}

        return [e.event for e in active_entries]

    def clear_ip(self, target_identifier: str, source_ip: str) -> None:
        """차단 조치 완료 후 해당 타깃/IP의 이력을 즉시 정리한다."""
        key = (target_identifier, source_ip)
        self._entries.pop(key, None)
        self._seen_event_ids.pop(key, None)

    def clear(self) -> None:
        """전체 윈도우 상태를 초기화한다 (테스트베드 격리용)."""
        self._entries.clear()
        self._seen_event_ids.clear()
