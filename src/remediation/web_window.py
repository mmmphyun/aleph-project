# CloudShield 상태 저장소: 배치 간 L7 웹 공격 누적 윈도우
# 소유자: 클라우드 A 담당
"""CloudWatch Logs 분할 배치 간 Nginx L7 웹 공격 이력 보존 슬라이딩 윈도우 모듈.

Why:
    CloudWatch Logs Subscription Filter는 버퍼 및 전송 정책에 따라
    짧은 간격 내 발생한 Nginx 웹 접근 로그를 여러 Lambda 배치 호출로 분할 전달함.
    무상태(Stateless)인 evaluate_web_rules는 현재 배치만 전달받을 경우
    디렉터리 스캐닝(10초 내 5개 이상 경로)과 같은 누적성 공격을 탐지하지 못하므로,
    DynamoDB 원자적 저장소와 타임스탬프 슬라이딩 윈도우를 활용해 분할 수신된 이벤트를 영속 집계함.
    또한 DynamoDB 미가용 또는 로컬 격리 테스트베드를 위해 인메모리 폴백 모드를 동시에 지원함.

Constraints:
    - 기본 윈도우 시간: 10초 (DEFAULT_WEB_WINDOW_SECONDS = 10.0).
    - DynamoDB 파티션 키: target_key (S) = WEB#{target_identifier}#{source_ip}.
    - 동일 이벤트 ID(CloudWatchLogEvent.id)는 중복 집계에서 원천 배제함.
    - 이벤트 기준 최신 타임스탬프로부터 10초를 초과한 만료 이벤트는 슬라이딩 조회 시 필터링됨.
"""

from __future__ import annotations

import logging
import os
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import boto3
from botocore.exceptions import ClientError

from contracts.events import NginxAccessLogEvent

logger = logging.getLogger(__name__)

DEFAULT_WEB_WINDOW_SECONDS = 10.0
DEFAULT_WEB_ATTACK_TABLE_NAME = "CloudShield-AuthFailure-Window"


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
    raw_message: str
    event: NginxAccessLogEvent


class WebAttackWindow:
    """Nginx L7 웹 접근 로그의 분할 배치 간 10초 슬라이딩 윈도우 관리 엔진.

    Why:
        복수의 Lambda 배치 호출 및 동시 실행 환경으로 나뉘어 전달되는 Nginx 로그를
        DynamoDB 영속 저장소 또는 인메모리 캐시를 통해 타깃 인스턴스 및 출발지 IP별로
        누적 보존하여, 10초 시간창에 걸친 디렉터리 스캐닝 등의 위협을 100% 탐지함.
    """

    def __init__(
        self,
        table_name: str | None = None,
        dynamodb_resource: Any = None,
        window_seconds: float = DEFAULT_WEB_WINDOW_SECONDS,
    ) -> None:
        self.window_seconds = window_seconds
        self.table_name = (
            table_name
            or os.getenv("WEB_ATTACK_TABLE_NAME")
            or os.getenv("AUTH_FAILURE_TABLE_NAME")
            or DEFAULT_WEB_ATTACK_TABLE_NAME
        )
        self._dynamodb = dynamodb_resource
        self._table: Any = None
        self._use_dynamodb = False

        if self._dynamodb is None:
            try:
                region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
                self._dynamodb = boto3.resource("dynamodb", region_name=region)
            except Exception:
                self._dynamodb = None

        if self._dynamodb is not None:
            # Why:
            #   Boto3 Table 리소스는 지연 생성(Lazy) 객체이므로 load()(DescribeTable) 호출
            #   없이 get_item/update_item을 즉시 실행할 수 있음.
            #   불필요한 사전 DescribeTable 호출을 배제하여 IAM 권한 누락으로 인한
            #   조용한 인메모리 폴백 전환을 방지하고 콜드스타트 지연을 제거함.
            self._table = self._dynamodb.Table(self.table_name)
            self._use_dynamodb = True

        # 인메모리 폴백 저장소
        self._entries: dict[tuple[str, str], list[_WebLogEntry]] = defaultdict(list)
        self._seen_event_ids: dict[tuple[str, str], set[str]] = defaultdict(set)

    def _get_target_key(self, target_identifier: str, source_ip: str) -> str:
        """DynamoDB 파티션 키 반환."""
        return f"WEB#{target_identifier}#{source_ip}"

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

        # 인메모리 캐시 확인 및 추가
        if event_id in self._seen_event_ids[key]:
            return False

        self._seen_event_ids[key].add(event_id)
        self._entries[key].append(
            _WebLogEntry(
                event_id=event_id,
                timestamp_epoch=timestamp_epoch,
                raw_message=event.raw_message,
                event=event,
            )
        )

        # DynamoDB 영속화
        if self._use_dynamodb and self._table is not None:
            target_key = self._get_target_key(target_identifier, source_ip)
            ts_ms = int(round(timestamp_epoch * 1000))
            now = int(time.time())
            expire_at = now + 300
            entry_dict = {
                "id": event_id,
                "ts": ts_ms,
                "raw": event.raw_message,
            }
            try:
                self._table.update_item(
                    Key={"target_key": target_key},
                    UpdateExpression=(
                        "SET events = list_append(if_not_exists(events, :empty), :new_entry), "
                        "expire_at = :exp, last_seen = :now"
                    ),
                    ExpressionAttributeValues={
                        ":new_entry": [entry_dict],
                        ":empty": [],
                        ":exp": expire_at,
                        ":now": now,
                    },
                )
            except ClientError as exc:
                logger.error("DynamoDB 웹 공격 이벤트 갱신 실패 (key=%s): %s", target_key, exc)

        return True

    def get_active_events(
        self,
        target_identifier: str,
        source_ip: str,
        reference_time: float | None = None,
    ) -> list[NginxAccessLogEvent]:
        """지정된 타깃/IP의 10초 슬라이딩 윈도우 내 유효 이벤트를 반환한다.

        Why:
            참조 시각(reference_time) 또는 최신 이벤트 시각을 기준으로
            window_seconds 이전의 만료된 이벤트를 필터링하여 반환함.
            조회 시 내부 상태를 영구 삭제하지 않아(Side-effect Free) 후속 평가에서
            데이터 유실이 발생하지 않음.
        """
        key = (target_identifier, source_ip)
        merged_entries: list[_WebLogEntry] = []
        seen_ids: set[str] = set()

        # 1. DynamoDB에서 영속 저장된 이벤트 로드
        if self._use_dynamodb and self._table is not None:
            target_key = self._get_target_key(target_identifier, source_ip)
            try:
                # Why:
                #   분산 Lambda 환경에서 앞선 배치가 기록한 최신 이벤트를 stale read 없이
                #   즉시 조회할 수 있도록 Strongly Consistent Read(ConsistentRead=True)를 강제함.
                res = self._table.get_item(
                    Key={"target_key": target_key},
                    ConsistentRead=True,
                )
                item = res.get("Item", {})
                raw_events = item.get("events", [])
                for d in raw_events:
                    eid = d.get("id")
                    if eid and eid not in seen_ids:
                        seen_ids.add(eid)
                        ts = float(d.get("ts", 0)) / 1000.0
                        raw_msg = d.get("raw", "")
                        parsed = NginxAccessLogEvent.parse_line(raw_msg)
                        if parsed:
                            merged_entries.append(
                                _WebLogEntry(
                                    event_id=eid,
                                    timestamp_epoch=ts,
                                    raw_message=raw_msg,
                                    event=parsed,
                                )
                            )
            except ClientError as exc:
                logger.error("DynamoDB 웹 공격 이력 조회 실패 (key=%s): %s", target_key, exc)

        # 2. 로컬 인메모리 엔트리 병합
        for entry in self._entries.get(key, []):
            if entry.event_id not in seen_ids:
                seen_ids.add(entry.event_id)
                merged_entries.append(entry)

        if not merged_entries:
            return []

        if reference_time is not None:
            ref_time = reference_time
        else:
            ref_time = max(e.timestamp_epoch for e in merged_entries)

        cutoff = ref_time - self.window_seconds
        active_entries = [e for e in merged_entries if cutoff <= e.timestamp_epoch <= ref_time]
        active_entries.sort(key=lambda e: e.timestamp_epoch)
        return [e.event for e in active_entries]

    def clear_ip(self, target_identifier: str, source_ip: str) -> None:
        """차단 조치 완료 후 해당 타깃/IP의 이력을 즉시 정리한다."""
        key = (target_identifier, source_ip)
        self._entries.pop(key, None)
        self._seen_event_ids.pop(key, None)

        if self._use_dynamodb and self._table is not None:
            target_key = self._get_target_key(target_identifier, source_ip)
            try:
                self._table.delete_item(Key={"target_key": target_key})
            except ClientError as exc:
                logger.error("DynamoDB 웹 공격 이력 삭제 실패 (key=%s): %s", target_key, exc)

    def clear(self) -> None:
        """전체 윈도우 상태를 초기화한다 (테스트베드 격리용)."""
        self._entries.clear()
        self._seen_event_ids.clear()
