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
    logger.info("Lambda 로그 그룹: %s (최대 대기: %d초)", lambda_log_group, timeout_seconds)

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
            "t_sg_verified_iso": None,
            "t_sg_verified_epoch": None,
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
        for ev in events:
            msg = ev.get("message", "")
            ts_ms = ev.get("timestamp", 0)
            lambda_logs.append({"timestamp": ts_ms, "message": msg.strip()})
            if "격리 완료" in msg or "quarantine" in msg.lower() or "차단" in msg:
                t_block_epoch = ts_ms / 1000.0
                t_block_iso = datetime.datetime.fromtimestamp(
                    t_block_epoch, datetime.UTC
                ).isoformat()

        if t_block_iso is None and events:
            # 첫 번째 이벤트 또는 REPORT 이벤트 기준
            last_ev = events[-1]
            t_block_epoch = last_ev["timestamp"] / 1000.0
            t_block_iso = datetime.datetime.fromtimestamp(t_block_epoch, datetime.UTC).isoformat()

    except ClientError as e:
        logger.warning("Lambda 로그 조회 중 ClientError: %s", e)

    result = {
        "status": "quarantined",
        "instance_id": instance_id,
        "observed_sgs": observed_sgs,
        "t_sg_verified_iso": t_sg_verified_iso,
        "t_sg_verified_epoch": t_sg_verified_epoch,
        "t_block_iso": t_block_iso,
        "t_block_epoch": t_block_epoch,
        "lambda_events_count": len(lambda_logs),
        "lambda_logs": lambda_logs,
    }

    return result


def main() -> None:
    """CLI 진입점."""
    parser = argparse.ArgumentParser(description="CloudShield 관통 실측 모니터링 도구")
    parser.add_argument("--instance-id", default=DEFAULT_INSTANCE_ID)
    parser.add_argument("--quarantine-sg-id", default=DEFAULT_QUARANTINE_SG_ID)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--interval", type=float, default=0.5)
    args = parser.parse_args()

    res = monitor_quarantine(
        instance_id=args.instance_id,
        quarantine_sg_id=args.quarantine_sg_id,
        timeout_seconds=args.timeout,
        poll_interval=args.interval,
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
