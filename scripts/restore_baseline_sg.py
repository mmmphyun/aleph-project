"""타깃 EC2 Baseline Security Group 원자적 롤백 복구 스크립트.

소유자: 클라우드 A (플랫폼 전담)

Why:
    시나리오 1 관통 대응 실측 완료 후, 격리 보안 그룹(Quarantine SG)으로 격리된
    타깃 EC2를 기존 운영 기준선 보안 그룹(Baseline SG)으로 즉각 원자적 복구하여
    테스트 인프라의 가용성을 회복하고 단절 복구 시점(T_restored)을 정밀 계측함.

Constraints:
    - 인스턴스당 단일 Baseline SG로 원자적 교체(modify_instance_attribute) 수행.
    - Boto3 호출 시 ClientError 정밀 처리 및 비정상 종료 코드(sys.exit(1)) 전파.
    - 복구 시점(T_restored)을 ISO-8601 및 Epoch 밀리초 단위로 정확히 계측 및 출력.

Side-effects / Edge-cases:
    - 이미 대상 SG가 Baseline SG와 일치할 경우 중복 API 호출 없이 멱등성(Idempotency) 유지.
    - 인스턴스가 존재하지 않거나 권한 부족 시 오류 메시지를 로깅하고 예외를 전파함.
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

# 기본 상수 정의 (CloudShield ap-southeast-2 환경 기준)
DEFAULT_INSTANCE_ID = "i-027b9d94be16b0d77"
DEFAULT_BASELINE_SG_ID = "sg-07d8f7ea689ecd95e"
DEFAULT_REGION = "ap-southeast-2"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("restore_baseline_sg")


def restore_baseline_security_group(
    instance_id: str = DEFAULT_INSTANCE_ID,
    baseline_sg_id: str = DEFAULT_BASELINE_SG_ID,
    ec2_client: Any = None,
) -> dict[str, Any]:
    """침해 타깃 EC2의 보안 그룹을 Baseline 보안 그룹으로 원자적 복구.

    Why:
        격리 보안 그룹(CloudShield-Quarantine-SG) 적용 상태를 해제하고,
        사전 정의된 정상 트래픽 보안 그룹으로 복원하여 서비스 재개 및
        복구 소요 시간(T_restored)을 계측함.

    Constraints:
        - instance_id: 'i-' 접두사로 시작하는 유효한 AWS EC2 인스턴스 ID.
        - baseline_sg_id: 'sg-' 접두사로 시작하는 유효한 AWS 보안 그룹 ID.
        - ec2_client: Boto3 EC2 클라이언트 인스턴스 (미제공 시 자동 생성).

    Side-effects / Edge-cases:
        - 대상 인스턴스 조회 실패 시 ClientError 또는 ValueError 발생.
        - modify_instance_attribute 호출 실패 시 ClientError를 전파하여 무음 실패 방지.
        - 보안 그룹 변경 직후 describe_instances 동기 검증을 통해 최종 상태 확정.
    """
    if ec2_client is None:
        region = os.getenv("AWS_DEFAULT_REGION", DEFAULT_REGION)
        profile = os.getenv("AWS_PROFILE")
        session = boto3.Session(profile_name=profile, region_name=region)
        ec2_client = session.client("ec2")

    start_time = time.perf_counter()

    try:
        # 1. 대상 인스턴스 현재 상태 및 보안 그룹 조회
        desc_res = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = desc_res.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            raise ValueError(f"대상 인스턴스를 찾을 수 없습니다: {instance_id}")

        instance = reservations[0]["Instances"][0]
        current_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
        logger.info(
            "인스턴스 %s 현재 보안 그룹 상태: %s (복구 목표: %s)",
            instance_id,
            current_sgs,
            baseline_sg_id,
        )

        # 2. 멱등성 검증: 이미 Baseline SG 단독 적용 상태인 경우
        if current_sgs == [baseline_sg_id]:
            restore_iso = datetime.datetime.now(datetime.UTC).isoformat()
            restore_epoch = time.time()
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.info(
                "이미 Baseline SG(%s)가 단독 적용되어 있습니다. (멱등 처리 완료)",
                baseline_sg_id,
            )
            return {
                "status": "unchanged",
                "instance_id": instance_id,
                "previous_security_groups": current_sgs,
                "current_security_groups": current_sgs,
                "baseline_sg_id": baseline_sg_id,
                "t_restored_iso": restore_iso,
                "t_restored_epoch": restore_epoch,
                "duration_ms": duration_ms,
            }

        # 3. 원자적 보안 그룹 복구 적용
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[baseline_sg_id],
        )

        # 4. 동기 재조회 및 적용 검증
        verify_res = ec2_client.describe_instances(InstanceIds=[instance_id])
        verified_instance = verify_res["Reservations"][0]["Instances"][0]
        verified_sgs = [sg["GroupId"] for sg in verified_instance.get("SecurityGroups", [])]

        if verified_sgs != [baseline_sg_id]:
            raise RuntimeError(
                f"보안 그룹 복구 검증 실패: Baseline SG 단독 적용 불일치 "
                f"(예상=[{baseline_sg_id}], 실제={verified_sgs})"
            )

        restore_iso = datetime.datetime.now(datetime.UTC).isoformat()
        restore_epoch = time.time()
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        logger.info(
            "인스턴스 %s Baseline SG 복구 완료: %s -> %s (소요 시간: %0.2f ms)",
            instance_id,
            current_sgs,
            verified_sgs,
            duration_ms,
        )

        return {
            "status": "success",
            "instance_id": instance_id,
            "previous_security_groups": current_sgs,
            "current_security_groups": verified_sgs,
            "baseline_sg_id": baseline_sg_id,
            "t_restored_iso": restore_iso,
            "t_restored_epoch": restore_epoch,
            "duration_ms": duration_ms,
        }

    except ClientError as e:
        logger.error("AWS EC2 API 호출 중 ClientError 발생: %s", e)
        raise


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """CLI 인자 파서 구성."""
    parser = argparse.ArgumentParser(
        description="타깃 EC2 Baseline Security Group 원자적 롤백 복구 도구"
    )
    parser.add_argument(
        "--instance-id",
        default=os.getenv("TARGET_INSTANCE_ID", DEFAULT_INSTANCE_ID),
        help=f"복구 대상 EC2 인스턴스 ID (기본값: {DEFAULT_INSTANCE_ID})",
    )
    parser.add_argument(
        "--baseline-sg-id",
        default=os.getenv("BASELINE_SG_ID", DEFAULT_BASELINE_SG_ID),
        help=f"복구할 Baseline 보안 그룹 ID (기본값: {DEFAULT_BASELINE_SG_ID})",
    )
    parser.add_argument(
        "--region",
        default=os.getenv("AWS_DEFAULT_REGION", DEFAULT_REGION),
        help=f"AWS 리전 (기본값: {DEFAULT_REGION})",
    )
    parser.add_argument(
        "--profile",
        default=os.getenv("AWS_PROFILE"),
        help="AWS CLI 프로필 명칭 (선택 사항)",
    )
    return parser.parse_args(argv)


def main() -> None:
    """CLI 진입점 함수."""
    args = parse_args()

    session_kwargs: dict[str, Any] = {"region_name": args.region}
    if args.profile:
        session_kwargs["profile_name"] = args.profile

    session = boto3.Session(**session_kwargs)
    ec2_client = session.client("ec2")

    try:
        result = restore_baseline_security_group(
            instance_id=args.instance_id,
            baseline_sg_id=args.baseline_sg_id,
            ec2_client=ec2_client,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if result["status"] not in ("success", "unchanged"):
            sys.exit(1)
    except Exception as e:
        logger.error("Baseline SG 복구 실패: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
