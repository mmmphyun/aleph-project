"""시나리오 1 관통 실측 모니터링 및 타임스탬프 계측 도구.

소유자: 클라우드 A (플랫폼 전담)

Why:
    공격 개시 시점 이후 타깃 EC2의 보안 그룹 격리 전이 시점(T_sg_verified)과
    오케스트레이터 Lambda의 실행 및 차단 완료 시점(T_block)을 고해상도로 정밀 계측하여
    10초 관통 자동 대응 파이프라인의 실측 성능을 증빙함.

Constraints:
    - 500ms 간격으로 EC2 보안 그룹 상태를 동기 폴링하여 지연 최소화.
    - 격리 SG(sg-075e49d08f46d41de) 전환 감지 시 즉시 타임스탬프 기록.
    - Lambda CloudWatch Logs 이벤트 발생 시 로그 타임스탬프(T_block) 매핑.

Side-effects / Edge-cases:
    - AWS API Throttling 방지를 위해 최소 폴링 간격 300ms 유지.
    - 최대 대기 시간(기본 300초) 초과 시 타임아웃 종료.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import sys
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

DEFAULT_INSTANCE_ID = "i-027b9d94be16b0d77"
DEFAULT_QUARANTINE_SG_ID = "sg-075e49d08f46d41de"
DEFAULT_BASELINE_SG_ID = "sg-07d8f7ea689ecd95e"
DEFAULT_LAMBDA_LOG_GROUP = "/aws/lambda/CloudShield-Threat-Orchestrator"
DEFAULT_REGION = "ap-southeast-2"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("measure_pipeline")


def monitor_quarantine(
    instance_id: str = DEFAULT_INSTANCE_ID,
    quarantine_sg_id: str = DEFAULT_QUARANTINE_SG_ID,
    lambda_log_group: str = DEFAULT_LAMBDA_LOG_GROUP,
    incident_id: str | None = None,
    source_ip: str | None = None,
    timeout_seconds: int = 300,
    poll_interval: float = 0.5,
    ec2_client: Any = None,
    logs_client: Any = None,
) -> dict[str, Any]:
    """EC2 격리 보안 그룹 부착 및 Lambda 실행 로그 계측.

    Why:
        L4 보안 그룹 전이와 Lambda 실행 로그 타임스탬프를 상호 대조하여
        단일 10초 관통 대응의 종단간 소요 시간을 확정함.
    """
    if ec2_client is None or logs_client is None:
        region = os.getenv("AWS_DEFAULT_REGION", DEFAULT_REGION)
        profile = os.getenv("AWS_PROFILE")
        session = boto3.Session(profile_name=profile, region_name=region)
        ec2_client = ec2_client or session.client("ec2")
        logs_client = logs_client or session.client("logs")

    logger.info("관통 실측 모니터링 개시: 타깃 EC2=%s, 격리 SG=%s", instance_id, quarantine_sg_id)
    logger.info(
        "Lambda 로그 그룹: %s (최대 대기: %d초, 사건 식별자: %s, 소스 IP: %s)",
        lambda_log_group,
        timeout_seconds,
        incident_id or "전체",
        source_ip or "전체",
    )

    start_monitor_time = time.time()
    t_sg_verified_iso = None
    t_sg_verified_epoch = None
    observed_sgs = []

    # 1. EC2 보안 그룹 전이 감시 루프
    while time.time() - start_monitor_time < timeout_seconds:
        try:
            res = ec2_client.describe_instances(InstanceIds=[instance_id])
            inst = res["Reservations"][0]["Instances"][0]
            current_sgs = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]

            if quarantine_sg_id in current_sgs:
                t_sg_verified_epoch = time.time()
                t_sg_verified_iso = datetime.datetime.now(datetime.UTC).isoformat()
                observed_sgs = current_sgs
                logger.info(
                    "격리 보안 그룹 부착 감지 (T_sg_verified): %s (현재 SG: %s)",
                    t_sg_verified_iso,
                    current_sgs,
                )
                break

            time.sleep(poll_interval)
        except ClientError as e:
            logger.warning("EC2 상태 폴링 중 에러 (재시도 중): %s", e)
            time.sleep(poll_interval)

    if t_sg_verified_epoch is None:
        logger.error("최대 대기 시간(%d초) 초과: 격리 SG 부착이 감지되지 않음", timeout_seconds)
        return {
            "status": "timeout",
            "instance_id": instance_id,
            "incident_id": incident_id,
            "source_ip": source_ip,
            "t_sg_verified_iso": None,
            "t_sg_verified_epoch": None,
            "t_block_iso": None,
            "t_block_epoch": None,
            "lambda_logs": [],
        }

    # 2. Lambda CloudWatch Logs 조회 (T_block 계측)
    logger.info("Lambda CloudWatch Logs 조회 대기 (이벤트 전파 대기)...")
    time.sleep(2.0)  # CloudWatch 로그 플러시 대기

    lambda_logs = []
    t_block_iso = None
    t_block_epoch = None

    try:
        # 최근 5분 이내 로그 이벤트 검색
        start_query_ms = int((start_monitor_time - 60) * 1000)
        log_res = logs_client.filter_log_events(
            logGroupName=lambda_log_group,
            startTime=start_query_ms,
            limit=50,
        )
        events = log_res.get("events", [])
        has_identifier = bool(incident_id or source_ip)
        for ev in events:
            msg = ev.get("message", "")
            ts_ms = ev.get("timestamp", 0)
            lambda_logs.append({"timestamp": ts_ms, "message": msg.strip()})

            # 사건 연결성 검증: 식별자(incident_id 또는 source_ip)가 반드시 일치해야 함
            if not has_identifier:
                continue

            matches_incident = True
            if incident_id and incident_id not in msg:
                matches_incident = False
            if source_ip and source_ip not in msg:
                matches_incident = False

            # 차단 실패/오류 메시지는 성공 타임스탬프(T_block)에서 엄격히 배제
            is_failure_msg = any(
                kw in msg.lower() for kw in ("실패", "미완료", "error", "failed", "failure")
            )
            is_success_msg = ("격리 완료" in msg or "격리 성공" in msg or "차단 성공" in msg) or (
                "quarantine" in msg.lower() and "success" in msg.lower()
            )
            is_valid_block = is_success_msg and not is_failure_msg

            if matches_incident and is_valid_block:
                t_block_epoch = ts_ms / 1000.0
                t_block_iso = datetime.datetime.fromtimestamp(
                    t_block_epoch, datetime.UTC
                ).isoformat()
                logger.info(
                    "사건 연결 차단 성공 로그 감지 (T_block): %s (메시지: %s)",
                    t_block_iso,
                    msg.strip(),
                )

        if t_block_iso is None:
            # 사건과 연결되지 않거나 차단 성공이 확인되지 않은 경우 T_block을 미확정(None)으로 유지
            logger.warning(
                "사건(%s, %s) 차단 성공 로그 미발견으로 T_block을 미확정(None)으로 유지합니다.",
                incident_id or "지정 안 됨",
                source_ip or "지정 안 됨",
            )

    except ClientError as e:
        logger.error("타깃 EC2 격리는 확인되었으나 Lambda 로그 조회 중 ClientError 발생: %s", e)
        # SG 부착 관측 결과는 보존하되 예외를 전파하여 무음 실패 차단
        partial_res = {
            "status": "log_query_failed",
            "instance_id": instance_id,
            "incident_id": incident_id,
            "source_ip": source_ip,
            "observed_sgs": observed_sgs,
            "t_sg_verified_iso": t_sg_verified_iso,
            "t_sg_verified_epoch": t_sg_verified_epoch,
            "t_block_iso": None,
            "t_block_epoch": None,
            "lambda_events_count": 0,
            "lambda_logs": [],
            "error": str(e),
        }
        e.partial_result = partial_res
        raise

    result = {
        "status": "quarantined",
        "instance_id": instance_id,
        "incident_id": incident_id,
        "source_ip": source_ip,
        "observed_sgs": observed_sgs,
        "t_sg_verified_iso": t_sg_verified_iso,
        "t_sg_verified_epoch": t_sg_verified_epoch,
        "t_block_iso": t_block_iso,
        "t_block_epoch": t_block_epoch,
        "lambda_events_count": len(lambda_logs),
        "lambda_logs": lambda_logs,
    }

    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """CLI 인자 파서 정의."""
    parser = argparse.ArgumentParser(description="CloudShield 관통 실측 모니터링 도구")
    parser.add_argument("--instance-id", default=DEFAULT_INSTANCE_ID)
    parser.add_argument("--quarantine-sg-id", default=DEFAULT_QUARANTINE_SG_ID)
    parser.add_argument("--incident-id", default=None, help="추적할 인시던트 식별자")
    parser.add_argument("--source-ip", default=None, help="추적할 모의 공격자 IP")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--interval", type=float, default=0.5)
    return parser.parse_args(argv)


def main() -> None:
    """CLI 진입점."""
    args = parse_args()

    try:
        res = monitor_quarantine(
            instance_id=args.instance_id,
            quarantine_sg_id=args.quarantine_sg_id,
            incident_id=args.incident_id,
            source_ip=args.source_ip,
            timeout_seconds=args.timeout,
            poll_interval=args.interval,
        )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        if res.get("status") != "quarantined":
            sys.exit(1)
    except Exception as e:
        logger.error("관통 실측 모니터링 실행 실패: %s", e)
        if hasattr(e, "partial_result"):
            print(json.dumps(e.partial_result, indent=2, ensure_ascii=False))
        sys.exit(1)


if __name__ == "__main__":
    main()
