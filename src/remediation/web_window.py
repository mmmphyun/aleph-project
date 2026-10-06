# CloudShield 상태 저장소: 배치 간 L7 웹 공격 누적 윈도우
# 소유자: 클라우드 A 담당
"""CloudWatch Logs 분할 배치 간 Nginx L7 웹 공격 이력 보존 슬라이딩 윈도우 모듈.

Why:
    CloudWatch Logs Subscription Filter는 버퍼 및 전송 정책에 따라
    짧은 간격 내 발생한 Nginx 웹 접근 로그를 여러 Lambda 배치 호출로 분할 전달함.
    무상태(Stateless)인 evaluate_web_rules는 현재 배치만 전달받을 경우
    디렉터리 스캐닝(10초 내 5개 이상 경로)과 같은 누적성 공격을 탐지하지 못하므로,
    DynamoDB 원자적 저장소와 타임스탬프 슬라이딩 윈도우를 활용해 분할 수신된 이벤트를 영속 집계함.
    특히 단일 항목 400 KB 크기 상한(ValidationException)에 의한 탐지 누락을 방어하기 위해
    10초 시간 버킷 파티셔닝(Two-Buckets)과 슬롯 기반 오버플로 청킹(Slot Chunking)을 채택하여
    버킷 포화 상태에서도 후속 공격을 안전하게 영속화함.

Constraints:
    - 기본 윈도우 시간: 10초 (DEFAULT_WEB_WINDOW_SECONDS = 10.0).
    - DynamoDB 파티션 키: target_key (S) = WEB#{target_identifier}#{source_ip}#{bucket_id}[#{slot}].
    - bucket_id = int(timestamp_epoch) // int(window_seconds).
    - 2-버킷 모델: 직전(bucket_id - 1) 및 현재 버킷 2개만 조회하여 10초 윈도우 보장.
    - 슬롯 분할: 단일 버킷 항목이 400 KB에 도달할 경우 슬롯 1~4로 오버플로 분할 저장.
    - 영속화 실패와 중복 이벤트 분리: 중복은 False 반환, 저장 실패는 PersistenceError 발생.
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
MAX_SLOTS_PER_BUCKET = 5


class PersistenceError(Exception):
    """DynamoDB 윈도우 영속화 실패 시 발생하는 예외."""


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
    """Nginx L7 웹 접근 로그의 2-버킷 슬라이딩 윈도우 관리 엔진.

    Why:
        복수의 Lambda 배치 호출 및 동시 실행 환경으로 나뉘어 전달되는 Nginx 로그를
        DynamoDB 시간 버킷 영속 저장소 또는 인메모리 캐시를 통해 타깃 인스턴스 및 출발지 IP별로
        누적 보존하여, 10초 시간창에 걸친 디렉터리 스캐닝 등의 위협을 100% 탐지함.
        시간 버킷 분할과 슬롯 오버플로 청킹으로 단일 항목 400 KB 제한 초과를 방지함.
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
            self._table = self._dynamodb.Table(self.table_name)
            self._use_dynamodb = True

        # 인메모리 폴백 저장소
        self._entries: dict[tuple[str, str], list[_WebLogEntry]] = defaultdict(list)
        self._seen_event_ids: dict[tuple[str, str], set[str]] = defaultdict(set)

    def _get_bucket_id(self, timestamp_epoch: float) -> int:
        """타임스탬프 기준 윈도우 시간 버킷 ID 산출."""
        return int(timestamp_epoch) // int(self.window_seconds)

    def _get_target_key(
        self,
        target_identifier: str,
        source_ip: str,
        bucket_id: int,
        slot: int = 0,
    ) -> str:
        """DynamoDB 시간 버킷 파티션 키 반환. 기본 슬롯은 0이며 포화 시 슬롯 번호 부착."""
        base_key = f"WEB#{target_identifier}#{source_ip}#{bucket_id}"
        return base_key if slot == 0 else f"{base_key}#{slot}"

    def add_event(
        self,
        target_identifier: str,
        source_ip: str,
        event_id: str,
        timestamp_epoch: float,
        event: NginxAccessLogEvent,
    ) -> bool:
        """이벤트를 윈도우에 추가한다.

        이벤트 ID가 이미 등록되어 있으면 무시하고 False를 반환한다(중복 스킵).
        DynamoDB 쓰기 실패 시 PersistenceError를 발생시켜 조용한 실패를 차단한다.
        단일 항목 400 KB 초과(ValidationException) 시 다음 슬롯으로 오버플로 저장한다.
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

        # DynamoDB 2-버킷 + 슬롯 오버플로 영속화
        if self._use_dynamodb and self._table is not None:
            bucket_id = self._get_bucket_id(timestamp_epoch)
            ts_ms = int(round(timestamp_epoch * 1000))
            now = int(time.time())
            expire_at = (bucket_id + 3) * int(self.window_seconds)
            entry_dict = {
                "id": event_id,
                "ts": ts_ms,
                "raw": event.raw_message,
            }

            persisted = False
            last_client_error: ClientError | None = None

            for slot in range(MAX_SLOTS_PER_BUCKET):
                target_key = self._get_target_key(
                    target_identifier, source_ip, bucket_id, slot=slot
                )
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
                    persisted = True
                    break
                except ClientError as exc:
                    err_code = exc.response.get("Error", {}).get("Code", "")
                    err_msg = exc.response.get("Error", {}).get("Message", "")
                    # 항목 크기 400 KB 상한 도달 시 다음 슬롯으로 전환
                    if err_code == "ValidationException" and (
                        "exceeded" in err_msg.lower() or "size" in err_msg.lower()
                    ):
                        logger.warning(
                            "버킷 슬롯 용량 포화(400KB), 다음 슬롯으로 전환 (key=%s, slot=%d)",
                            target_key,
                            slot,
                        )
                        continue
                    last_client_error = exc
                    logger.error("DynamoDB 웹 공격 이벤트 갱신 실패 (key=%s): %s", target_key, exc)
                    break

            if not persisted:
                err_detail = (
                    str(last_client_error)
                    if last_client_error
                    else f"All {MAX_SLOTS_PER_BUCKET} slots exhausted"
                )
                raise PersistenceError(f"DynamoDB 이벤트 영속화 실패: {err_detail}")

        return True

    def get_active_events(
        self,
        target_identifier: str,
        source_ip: str,
        reference_time: float | None = None,
    ) -> list[NginxAccessLogEvent]:
        """지정된 타깃/IP의 10초 슬라이딩 윈도우 내 유효 이벤트를 반환한다.

        Why:
            2-버킷의 모든 슬롯(기본 및 오버플로)을 Strongly Consistent Read로 조회하여
            버킷 포화 상태에서도 분할 저장된 이벤트를 누락 없이 병합함.
        """
        key = (target_identifier, source_ip)
        merged_entries: list[_WebLogEntry] = []
        seen_ids: set[str] = set()

        if reference_time is not None:
            ref_time = reference_time
        else:
            in_mem_entries = self._entries.get(key, [])
            ref_time = (
                max((e.timestamp_epoch for e in in_mem_entries), default=time.time())
                if in_mem_entries
                else time.time()
            )

        # 1. DynamoDB 2-버킷(직전 버킷, 현재 버킷) 및 슬롯에서 이벤트 로드
        if self._use_dynamodb and self._table is not None:
            cur_bucket = self._get_bucket_id(ref_time)
            prev_bucket = cur_bucket - 1
            for b_id in (prev_bucket, cur_bucket):
                for slot in range(MAX_SLOTS_PER_BUCKET):
                    target_key = self._get_target_key(target_identifier, source_ip, b_id, slot=slot)
                    try:
                        res = self._table.get_item(
                            Key={"target_key": target_key},
                            ConsistentRead=True,
                        )
                        item = res.get("Item")
                        if not item:
                            if slot > 0:
                                break
                            continue
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
                        logger.error(
                            "DynamoDB 웹 공격 이력 조회 실패 (key=%s): %s", target_key, exc
                        )

        # 2. 로컬 인메모리 엔트리 병합
        for entry in self._entries.get(key, []):
            if entry.event_id not in seen_ids:
                seen_ids.add(entry.event_id)
                merged_entries.append(entry)

        if not merged_entries:
            return []

        cutoff = ref_time - self.window_seconds
        active_entries = [e for e in merged_entries if cutoff <= e.timestamp_epoch <= ref_time]
        active_entries.sort(key=lambda e: e.timestamp_epoch)
        return [e.event for e in active_entries]

    def clear_ip(
        self,
        target_identifier: str,
        source_ip: str,
        reference_time: float | None = None,
    ) -> None:
        """차단 조치 완료 후 해당 타깃/IP의 최근 시간 버킷 및 슬롯 이력을 정리한다."""
        key = (target_identifier, source_ip)
        self._entries.pop(key, None)
        self._seen_event_ids.pop(key, None)

        if self._use_dynamodb and self._table is not None:
            now = reference_time if reference_time is not None else time.time()
            cur_bucket = self._get_bucket_id(now)
            for offset in (-2, -1, 0, 1):
                b_id = cur_bucket + offset
                for slot in range(MAX_SLOTS_PER_BUCKET):
                    target_key = self._get_target_key(target_identifier, source_ip, b_id, slot=slot)
                    try:
                        self._table.delete_item(Key={"target_key": target_key})
                    except ClientError as exc:
                        logger.error(
                            "DynamoDB 웹 공격 이력 삭제 실패 (key=%s): %s", target_key, exc
                        )

    def clear(self) -> None:
        """전체 윈도우 상태를 초기화한다 (테스트베드 격리용)."""
        self._entries.clear()
        self._seen_event_ids.clear()
