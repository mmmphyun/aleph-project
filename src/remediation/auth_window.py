# CloudShield 상태 저장소: 배치 간 인증 실패 누적 윈도우
# 소유자: 클라우드 A 담당
"""DynamoDB 2-버킷 기반 타임스탬프 슬라이딩 윈도우(Sliding Log over Two-Buckets) 관리 모듈.

Why:
    CloudWatch Logs Subscription Filter는 로그 볼륨 및 전송 버퍼 정책에 따라
    짧은 간격 내 발생한 인증 실패 이벤트를 여러 Lambda 호출 배치로 분할 전달함.
    무상태(Stateless)인 Lambda 메모리만으로는 분할 배치 간 인증 실패를 누적할 수 없으므로,
    DynamoDB 원자적 저장소와 5분 TTL 윈도우를 활용해 분할 수신된 이벤트를 영속 집계함.

    [2-버킷 슬라이딩 로그 하이브리드 모델 채택 근거]:
    단일 키 기반 조건부 갱신(OCC)은 동시 인입 시 Lost Update와 재시도 지연을 유발하며,
    단순 고정 텀블링 윈도우는 300초 경계면에 걸친 공격에 대해 분할 탐지 누락을 유발함.
    또한 단순 정수 카운터 기반 시간 감쇠 모델은 비균등 버스트 트래픽에서 탐지 누락과 오탐이 발생함.
    이에 따라 시간 버킷(epoch // 300) 파티셔닝으로 조건식 없는 원자적 쓰기를 보장하고,
    버킷 내에 이벤트 발생 타임스탬프를 보존하여 조회 시 300초 유효 구간을 정확하게 필터링함으로써
    동시성 충돌 0%와 탐지 정밀도를 동시에 달성함.

Constraints:
    - DynamoDB 테이블은 파티션 키 target_key(문자열)를 필수로 보유해야 함.
    - 파티션 키 형식:
      * Brute Force: BF#{source_ip}#{username}#{bucket_id}
      * Password Spraying: SPRAY#{source_ip}#{bucket_id}
      * 여기서 bucket_id = epoch_seconds // window_seconds
    - TTL 속성명은 expire_at(Unix Epoch 초 단위 정수, 10분 TTL)을 사용함.
    - 단일 계정 집중 공격(SSH_BRUTE_FORCE) 임계치: 5회.
    - 다중 계정 공격(SSH_PASSWORD_SPRAYING) 임계치: 2개 고유 계정.
    - 윈도우 유효 시간: 300초 (5분).
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

DEFAULT_AUTH_FAILURE_TABLE_NAME = "CloudShield-AuthFailure-Window"
BRUTE_FORCE_THRESHOLD = 5
PASSWORD_SPRAYING_THRESHOLD = 2
DEFAULT_WINDOW_SECONDS = 300


class AuthFailureWindow:
    """DynamoDB 기반 2-버킷 타임스탬프 슬라이딩 윈도우 집계 엔진.

    Why:
        복수의 Lambda 인스턴스가 병렬 실행되더라도 조건식 없는 원자적 연산
        (Atomic ADD/list_append)을 통해 동시성 경쟁(Race Condition)을 차단하며,
        개별 타임스탬프 보존을 통해 300초 윈도우 경계면 오탐 및 누락을 원천 배제함.
    """

    def __init__(
        self,
        table_name: str | None = None,
        dynamodb_resource: Any = None,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        """AuthFailureWindow 초기화.

        Constraints:
            - table_name이 주어지지 않은 경우 AUTH_FAILURE_TABLE_NAME 환경변수 또는 기본값 사용.
            - dynamodb_resource가 주어지지 않은 경우 boto3.resource("dynamodb")로 자동 생성.
        """
        self.table_name = (
            table_name or os.getenv("AUTH_FAILURE_TABLE_NAME") or DEFAULT_AUTH_FAILURE_TABLE_NAME
        )
        self.window_seconds = window_seconds

        if dynamodb_resource is None:
            region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
            self._dynamodb = boto3.resource("dynamodb", region_name=region)
        else:
            self._dynamodb = dynamodb_resource

        self._table = self._dynamodb.Table(self.table_name)
        self._last_seen_timestamps: dict[str, int] = {}

    def _get_bucket_id(self, timestamp_epoch: float | None = None) -> int:
        """주어진 타임스탬프 또는 현재 시각 기준 윈도우 버킷 ID 산출."""
        t = timestamp_epoch if timestamp_epoch is not None else time.time()
        return int(t) // self.window_seconds

    def _get_bf_key(
        self,
        source_ip: str,
        username: str,
        bucket_id: int | None = None,
        timestamp_epoch: float | None = None,
    ) -> str:
        """단일 계정 무차별 대입 버킷 파티션 키 생성."""
        if bucket_id is not None:
            b_id = bucket_id
        else:
            t = (
                timestamp_epoch
                if timestamp_epoch is not None
                else self._last_seen_timestamps.get(source_ip, time.time())
            )
            b_id = self._get_bucket_id(t)
        return f"BF#{source_ip}#{username}#{b_id}"

    def _get_spray_key(
        self,
        source_ip: str,
        bucket_id: int | None = None,
        timestamp_epoch: float | None = None,
    ) -> str:
        """다중 계정 패스워드 스프레잉 버킷 파티션 키 생성."""
        if bucket_id is not None:
            b_id = bucket_id
        else:
            t = (
                timestamp_epoch
                if timestamp_epoch is not None
                else self._last_seen_timestamps.get(source_ip, time.time())
            )
            b_id = self._get_bucket_id(t)
        return f"SPRAY#{source_ip}#{b_id}"

    def record_failure(
        self,
        source_ip: str,
        username: str,
        timestamp_epoch: float | None = None,
        count: int = 1,
    ) -> dict[str, Any]:
        """단일 인증 실패 이벤트를 현재 시간 버킷에 락 프리(Lock-free) 원자적으로 누적.

        Why:
            버킷화된 파티션 키를 사용하므로 이전 윈도우 만료 여부를 판별하는 조건부 갱신이 불필요함.
            카운터/셋과 함께 발생 타임스탬프(Unix Epoch 초) 리스트를 원자적으로 append하여
            후속 조회 시 300초 슬라이딩 유효 구간을 정확하게 필터링할 수 있도록 지원함.
            조건식 없는 단 1회 호출로 충돌률 0%의 원자적 갱신을 달성함.

        Constraints:
            - source_ip: IPv4 주소 문자열.
            - username: 시도된 사용자 계정명.
            - count: 누적할 실패 횟수 (기본값 1).
            - TTL 속성(expire_at)은 버킷 수명(2개 버킷, 10분) 후 자동 소각되도록 설정.
        """
        now = int(timestamp_epoch if timestamp_epoch is not None else time.time())
        self._last_seen_timestamps[source_ip] = now
        bucket_id = now // self.window_seconds
        expire_at = (bucket_id + 2) * self.window_seconds
        bf_key = self._get_bf_key(source_ip, username, bucket_id=bucket_id)
        spray_key = self._get_spray_key(source_ip, bucket_id=bucket_id)

        accumulated_result: dict[str, Any] = {
            "source_ip": source_ip,
            "username": username,
            "bf_count": 0,
            "spray_users": set(),
            "bf_quarantined": False,
            "spray_quarantined": False,
        }

        # 1. 단일 계정 Brute Force 원자적 카운터 및 타임스탬프 누적 (조건식 없는 1 RTT Upsert)
        new_timestamps = [now] * count
        try:
            res_bf = self._table.update_item(
                Key={"target_key": bf_key},
                UpdateExpression=(
                    "ADD failure_count :inc "
                    "SET timestamps = list_append(if_not_exists(timestamps, :empty), :new_ts), "
                    "expire_at = :exp, last_seen = :now"
                ),
                ExpressionAttributeValues={
                    ":inc": count,
                    ":new_ts": new_timestamps,
                    ":empty": [],
                    ":exp": expire_at,
                    ":now": now,
                },
                ReturnValues="ALL_NEW",
            )
            attrs_bf = res_bf.get("Attributes", {})
            accumulated_result["bf_count"] = int(attrs_bf.get("failure_count", 0))
            accumulated_result["bf_quarantined"] = bool(attrs_bf.get("quarantined", False))
        except ClientError as e:
            logger.error("DynamoDB Brute Force 카운터 갱신 실패 (key=%s): %s", bf_key, e)

        # 2. 다중 계정 Password Spraying 고유 계정 집합 및 시도 기록 누적 (조건식 없는 1 RTT Upsert)
        new_attempts = [{"user": username, "ts": now}] * count
        try:
            res_spray = self._table.update_item(
                Key={"target_key": spray_key},
                UpdateExpression=(
                    "ADD usernames :user_set "
                    "SET attempts = list_append(if_not_exists(attempts, :empty), :new_attempts), "
                    "expire_at = :exp, last_seen = :now"
                ),
                ExpressionAttributeValues={
                    ":user_set": {username},
                    ":new_attempts": new_attempts,
                    ":empty": [],
                    ":exp": expire_at,
                    ":now": now,
                },
                ReturnValues="ALL_NEW",
            )
            attrs_spray = res_spray.get("Attributes", {})
            accumulated_result["spray_users"] = set(attrs_spray.get("usernames", set()))
            accumulated_result["spray_quarantined"] = bool(attrs_spray.get("quarantined", False))
        except ClientError as e:
            logger.error(
                "DynamoDB Password Spraying 계정 집합 갱신 실패 (key=%s): %s",
                spray_key,
                e,
            )

        return accumulated_result

    def check_threat(
        self,
        source_ip: str,
        username: str,
        timestamp_epoch: float | None = None,
    ) -> tuple[bool, str | None, str]:
        """현재 버킷과 직전 버킷의 타임스탬프 슬라이딩 윈도우를 기반으로 위협 임계치 도달 여부 판정.

        Why:
            단순 정수 카운터 기반 시간 감쇠는 버스트 공격의 탐지 누락 및
            만료 이벤트의 오탐을 유발함.
            따라서 현재 버킷과 직전 버킷에 보존된 개별 이벤트 타임스탬프를 조회하여
            실제 유효 윈도우(now - window_seconds <= t <= now) 내에 인입된 실패 횟수 및
            고유 계정 수를 정밀 필터링하여 임계치 도달 여부를 정확하게 판정함.
            ConsistentRead=True를 통해 리더 노드로부터 최신 데이터를 강하게 일관되게 조회함.

        Returns:
            (is_threat: bool, rule_name: str | None, target_key: str)
            - rule_name: "SSH_BRUTE_FORCE" 또는 "SSH_PASSWORD_SPRAYING" 또는 None.
            - target_key: 조치 완료 마킹 시 사용할 현재 버킷 파티션 키.
        """
        if timestamp_epoch is None:
            now = self._last_seen_timestamps.get(source_ip, int(time.time()))
        else:
            now = int(timestamp_epoch)
        curr_bucket = now // self.window_seconds
        prev_bucket = curr_bucket - 1
        cutoff = now - self.window_seconds

        bf_curr_key = self._get_bf_key(source_ip, username, bucket_id=curr_bucket)
        bf_prev_key = self._get_bf_key(source_ip, username, bucket_id=prev_bucket)

        spray_curr_key = self._get_spray_key(source_ip, bucket_id=curr_bucket)
        spray_prev_key = self._get_spray_key(source_ip, bucket_id=prev_bucket)

        # 1. SSH_BRUTE_FORCE 우선 검사 (현재 + 직전 버킷 강한 일관성 읽기)
        try:
            res_curr = self._table.get_item(Key={"target_key": bf_curr_key}, ConsistentRead=True)
            res_prev = self._table.get_item(Key={"target_key": bf_prev_key}, ConsistentRead=True)

            item_curr = res_curr.get("Item", {})
            item_prev = res_prev.get("Item", {})

            # 이미 어느 한 버킷이라도 격리 완료 처리되었으면 중복 차단 방지
            is_quarantined = bool(item_curr.get("quarantined", False)) or bool(
                item_prev.get("quarantined", False)
            )

            if not is_quarantined:
                # 타임스탬프 리스트가 있으면 정밀 유효 구간(t >= cutoff) 필터링,
                # 없으면 failure_count 폴백
                ts_curr = item_curr.get("timestamps")
                ts_prev = item_prev.get("timestamps")

                if ts_curr is not None or ts_prev is not None:
                    all_ts = (ts_curr or []) + (ts_prev or [])
                    valid_count = sum(1 for t in all_ts if int(t) >= cutoff)
                else:
                    valid_count = int(item_curr.get("failure_count", 0))

                if valid_count >= BRUTE_FORCE_THRESHOLD:
                    return True, "SSH_BRUTE_FORCE", bf_curr_key
        except ClientError as e:
            logger.error("DynamoDB Brute Force 상태 조회 실패: %s", e)

        # 2. SSH_PASSWORD_SPRAYING 차순위 검사 (현재 + 직전 버킷 강한 일관성 읽기)
        try:
            res_s_curr = self._table.get_item(
                Key={"target_key": spray_curr_key}, ConsistentRead=True
            )
            res_s_prev = self._table.get_item(
                Key={"target_key": spray_prev_key}, ConsistentRead=True
            )

            item_s_curr = res_s_curr.get("Item", {})
            item_s_prev = res_s_prev.get("Item", {})

            is_quarantined_spray = bool(item_s_curr.get("quarantined", False)) or bool(
                item_s_prev.get("quarantined", False)
            )

            if not is_quarantined_spray:
                # attempts 리스트가 있으면 정밀 유효 구간 고유 계정 필터링, 없으면 usernames 폴백
                attempts_curr = item_s_curr.get("attempts")
                attempts_prev = item_s_prev.get("attempts")

                if attempts_curr is not None or attempts_prev is not None:
                    all_attempts = (attempts_curr or []) + (attempts_prev or [])
                    valid_users = {
                        str(att["user"]) for att in all_attempts if int(att.get("ts", 0)) >= cutoff
                    }
                    users_count = len(valid_users)
                else:
                    users_count = len(set(item_s_curr.get("usernames", set())))

                if users_count >= PASSWORD_SPRAYING_THRESHOLD:
                    return True, "SSH_PASSWORD_SPRAYING", spray_curr_key
        except ClientError as e:
            logger.error("DynamoDB Password Spraying 상태 조회 실패: %s", e)

        return False, None, ""

    def mark_quarantined(self, target_key: str) -> bool:
        """해당 공격 타깃에 대한 격리 조치가 완료되었음을 현재 버킷 레코드에 마킹.

        Why:
            동일 윈도우 내에서 후속 실패 로그가 추가로 인입되더라도 중복 격리 API 호출
            (ModifyInstanceAttribute / UpdateIPSet)을 억제하여 멱등성을 보장함.
        """
        try:
            self._table.update_item(
                Key={"target_key": target_key},
                UpdateExpression="SET quarantined = :val",
                ExpressionAttributeValues={":val": True},
            )
            return True
        except ClientError as e:
            logger.error("DynamoDB 격리 완료 플래그 마킹 실패 (key=%s): %s", target_key, e)
            return False
