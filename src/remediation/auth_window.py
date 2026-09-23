# CloudShield 상태 저장소: 배치 간 인증 실패 누적 윈도우
# 소유자: 클라우드 A 담당
"""DynamoDB 원자적 카운터(Atomic Counter) 기반 5분 슬라이딩 윈도우 관리 모듈.

Why:
    CloudWatch Logs Subscription Filter는 로그 볼륨 및 전송 버퍼 정책에 따라
    짧은 간격 내 발생한 인증 실패 이벤트를 여러 Lambda 호출 배치로 분할 전달함.
    무상태(Stateless)인 Lambda 메모리만으로는 분할 배치 간 인증 실패를 누적할 수 없으므로,
    DynamoDB 원자적 카운터와 5분 TTL 윈도우를 활용해 분할 수신된 이벤트를 영속 집계하여
    단일 세션 176ms 만에 종료되는 SSH 공격에 대한 사후 L4 원자적 격리를 보장함.

Constraints:
    - DynamoDB 테이블은 파티션 키 target_key(문자열)를 필수로 보유해야 함.
    - TTL 속성명은 expire_at(Unix Epoch 초 단위 정수)을 사용함.
    - 단일 계정 집중 공격(SSH_BRUTE_FORCE) 임계치: 5회.
    - 다중 계정 공격(SSH_PASSWORD_SPRAYING) 임계치: 2개 고유 계정.
    - 윈도우 유효 시간: 300초 (5분).
"""

from __future__ import annotations

import logging
import os
import random
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

DEFAULT_AUTH_FAILURE_TABLE_NAME = "CloudShield-AuthFailure-Window"
BRUTE_FORCE_THRESHOLD = 5
PASSWORD_SPRAYING_THRESHOLD = 2
DEFAULT_WINDOW_SECONDS = 300
MAX_OCC_RETRIES = 8


class AuthFailureWindow:
    """DynamoDB 기반 인증 실패 윈도우 집계 엔진.

    Why:
        복수의 Lambda 인스턴스가 병렬 실행되더라도 DynamoDB update_item의 원자적 연산
        (Atomic ADD)을 통해 동시성 경쟁(Race Condition) 없이 정확한 실패 횟수를 누적함.
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

    def _get_bf_key(self, source_ip: str, username: str) -> str:
        """단일 계정 무차별 대입 집계용 파티션 키 생성."""
        return f"BF#{source_ip}#{username}"

    def _get_spray_key(self, source_ip: str) -> str:
        """다중 계정 패스워드 스프레잉 집계용 파티션 키 생성."""
        return f"SPRAY#{source_ip}"

    def record_failure(
        self,
        source_ip: str,
        username: str,
        timestamp_epoch: float | None = None,
        count: int = 1,
    ) -> dict[str, Any]:
        """단일 인증 실패 이벤트를 윈도우 테이블에 원자적으로 기록 및 누적.

        Why:
            기존 레코드의 만료 시각(expire_at)이 경과한 경우 이전 카운터를 즉시 리셋하고
            새 윈도우를 개설하며, 유효 시간창 내 인입된 이벤트는 원자적 카운터(ADD)로 합산함.

        Constraints:
            - source_ip: IPv4 주소 문자열.
            - username: 시도된 사용자 계정명.
            - count: 누적할 실패 횟수 (기본값 1).

        Side-effects / Edge-cases:
            - 조건부 업데이트 실패(ConditionalCheckFailedException) 시 신규 윈도우로 초기화.
            - DynamoDB 장애(ClientError) 발생 시 로그를 기록하고 빈 결과를 반환하여
              호출부 중단을 방지함.
        """
        now = int(timestamp_epoch if timestamp_epoch is not None else time.time())
        expire_at = now + self.window_seconds
        bf_key = self._get_bf_key(source_ip, username)
        spray_key = self._get_spray_key(source_ip)

        accumulated_result: dict[str, Any] = {
            "source_ip": source_ip,
            "username": username,
            "bf_count": 0,
            "spray_users": set(),
            "bf_quarantined": False,
            "spray_quarantined": False,
        }

        # 1. 단일 계정 Brute Force 원자적 카운터 누적 (동시성 CAS 재시도 루프)
        for attempt in range(MAX_OCC_RETRIES):
            try:
                try:
                    # 1-1. 기존 유효 윈도우 내 원자적 증가 시도
                    res_bf = self._table.update_item(
                        Key={"target_key": bf_key},
                        UpdateExpression="ADD failure_count :inc SET last_seen = :now",
                        ConditionExpression="attribute_exists(target_key) AND expire_at >= :now",
                        ExpressionAttributeValues={
                            ":inc": count,
                            ":now": now,
                        },
                        ReturnValues="ALL_NEW",
                    )
                    attrs_bf = res_bf.get("Attributes", {})
                    accumulated_result["bf_count"] = int(attrs_bf.get("failure_count", 0))
                    accumulated_result["bf_quarantined"] = bool(attrs_bf.get("quarantined", False))
                    break
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                        # 1-2. 만료되었거나 미존재 시 원자적 신규 윈도우 개설 시도
                        # 동시 호출 덮어쓰기(Lost Update) 방지를 위해
                        # 키 미존재 또는 기만료 조건 명시
                        res_bf = self._table.update_item(
                            Key={"target_key": bf_key},
                            UpdateExpression=(
                                "SET failure_count = :inc, window_start = :now, "
                                "expire_at = :expire_at, last_seen = :now, "
                                "quarantined = :quarantined"
                            ),
                            ConditionExpression=(
                                "attribute_not_exists(target_key) OR expire_at < :now"
                            ),
                            ExpressionAttributeValues={
                                ":inc": count,
                                ":now": now,
                                ":expire_at": expire_at,
                                ":quarantined": False,
                            },
                            ReturnValues="ALL_NEW",
                        )
                        attrs_bf = res_bf.get("Attributes", {})
                        accumulated_result["bf_count"] = int(attrs_bf.get("failure_count", 0))
                        bf_quar = bool(attrs_bf.get("quarantined", False))
                        accumulated_result["bf_quarantined"] = bf_quar
                        break
                    raise
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                    # 다른 동시 Lambda가 먼저 윈도우를 개설한 경우 다음 루프에서 ADD로 재시도
                    if attempt < MAX_OCC_RETRIES - 1:
                        time.sleep(random.uniform(0.01, 0.05))
                        continue
                logger.error("DynamoDB Brute Force 카운터 갱신 실패 (key=%s): %s", bf_key, e)
                break

        # 2. 다중 계정 Password Spraying 고유 계정 집합 누적 (동시성 CAS 재시도 루프)
        for attempt in range(MAX_OCC_RETRIES):
            try:
                try:
                    # 2-1. 기존 유효 윈도우 내 계정 집합(String Set) 원자적 추가
                    res_spray = self._table.update_item(
                        Key={"target_key": spray_key},
                        UpdateExpression="ADD usernames :user_set SET last_seen = :now",
                        ConditionExpression="attribute_exists(target_key) AND expire_at >= :now",
                        ExpressionAttributeValues={
                            ":user_set": {username},
                            ":now": now,
                        },
                        ReturnValues="ALL_NEW",
                    )
                    attrs_spray = res_spray.get("Attributes", {})
                    accumulated_result["spray_users"] = set(attrs_spray.get("usernames", set()))
                    spray_quar = bool(attrs_spray.get("quarantined", False))
                    accumulated_result["spray_quarantined"] = spray_quar
                    break
                except ClientError as e:
                    if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                        # 2-2. 만료되었거나 미존재 시 원자적 신규 윈도우 개설 시도
                        res_spray = self._table.update_item(
                            Key={"target_key": spray_key},
                            UpdateExpression=(
                                "SET usernames = :user_set, window_start = :now, "
                                "expire_at = :expire_at, last_seen = :now, "
                                "quarantined = :quarantined"
                            ),
                            ConditionExpression=(
                                "attribute_not_exists(target_key) OR expire_at < :now"
                            ),
                            ExpressionAttributeValues={
                                ":user_set": {username},
                                ":now": now,
                                ":expire_at": expire_at,
                                ":quarantined": False,
                            },
                            ReturnValues="ALL_NEW",
                        )
                        attrs_spray = res_spray.get("Attributes", {})
                        accumulated_result["spray_users"] = set(attrs_spray.get("usernames", set()))
                        spray_quar = bool(attrs_spray.get("quarantined", False))
                        accumulated_result["spray_quarantined"] = spray_quar
                        break
                    raise
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                    # 다른 동시 Lambda가 먼저 윈도우를 개설한 경우 다음 루프에서 ADD로 재시도
                    if attempt < MAX_OCC_RETRIES - 1:
                        time.sleep(random.uniform(0.01, 0.05))
                        continue
                logger.error(
                    "DynamoDB Password Spraying 계정 집합 갱신 실패 (key=%s): %s",
                    spray_key,
                    e,
                )
                break

        return accumulated_result

    def check_threat(
        self,
        source_ip: str,
        username: str,
    ) -> tuple[bool, str | None, str]:
        """현재 윈도우 누적 상태를 바탕으로 위협 임계치 도달 여부 판정.

        Why:
            단일 배치에서 임계치에 미달했더라도 이전 분할 배치와 합산된 횟수가
            임계치(5회 또는 2개 계정)를 초과하는 즉시 탐지 신호를 발생시킴.
            보안 룰 우선순위 원칙에 따라 더 위험한 SSH_BRUTE_FORCE를 우선 평가함.
            ConsistentRead=True를 지정하여 스토리지 복제 지연으로 인한 Stale Read를 원천 차단함.

        Returns:
            (is_threat: bool, rule_name: str | None, target_key: str)
            - rule_name: "SSH_BRUTE_FORCE" 또는 "SSH_PASSWORD_SPRAYING" 또는 None.
            - target_key: 조치 완료 마킹 시 사용할 파티션 키.
        """
        bf_key = self._get_bf_key(source_ip, username)
        spray_key = self._get_spray_key(source_ip)

        # 1. SSH_BRUTE_FORCE 우선 검사 (강한 일관성 읽기)
        try:
            res_bf = self._table.get_item(Key={"target_key": bf_key}, ConsistentRead=True)
            item_bf = res_bf.get("Item")
            if item_bf:
                count = int(item_bf.get("failure_count", 0))
                quarantined = bool(item_bf.get("quarantined", False))
                if count >= BRUTE_FORCE_THRESHOLD and not quarantined:
                    return True, "SSH_BRUTE_FORCE", bf_key
        except ClientError as e:
            logger.error("DynamoDB Brute Force 상태 조회 실패 (key=%s): %s", bf_key, e)

        # 2. SSH_PASSWORD_SPRAYING 차순위 검사 (강한 일관성 읽기)
        try:
            res_spray = self._table.get_item(Key={"target_key": spray_key}, ConsistentRead=True)
            item_spray = res_spray.get("Item")
            if item_spray:
                usernames = set(item_spray.get("usernames", set()))
                quarantined = bool(item_spray.get("quarantined", False))
                if len(usernames) >= PASSWORD_SPRAYING_THRESHOLD and not quarantined:
                    return True, "SSH_PASSWORD_SPRAYING", spray_key
        except ClientError as e:
            logger.error("DynamoDB Password Spraying 상태 조회 실패 (key=%s): %s", spray_key, e)

        return False, None, ""

    def mark_quarantined(self, target_key: str) -> bool:
        """해당 공격 타깃에 대한 격리 조치가 완료되었음을 상태 테이블에 마킹.

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
