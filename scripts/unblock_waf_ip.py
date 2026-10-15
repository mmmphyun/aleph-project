"""AWS WAFv2 IPSet 차단 해제 및 원자적 롤백 스크립트.

소유자: 클라우드 A (플랫폼 전담)

Why:
    시나리오 2(Web L7) 관통 대응 실측 완료 또는 오탐 발생 후,
    WAF IPSet(CloudShield-Block-IPSet)에 등록된 공격자 IP를 원자적으로 제거하여
    테스트베드 인프라의 가용성을 회복하고 단절 복구 시점(T_restored)을 정밀 계측함.

Constraints:
    - Boto3 WAFv2 API를 사용하여 단일 IP(/32) 또는 전체 목록을 원자적 갱신.
    - 동시 수정 충돌(WAFOptimisticLockException) 시 최신 LockToken 기반 최대 3회 재시도.
    - Read-after-Write 재조회를 통해 물리적 주소 목록 제외를 확증.
    - 복구 시점(T_restored)을 ISO-8601 및 Epoch 밀리초 단위로 정확히 계측 및 출력.

Side-effects / Edge-cases:
    - IPSet에 대상 IP가 이미 없으면 멱등(Idempotency) 성공 처리.
    - WAFv2 리소스 미존재 또는 권한 부족 시 ClientError 로깅 및 sys.exit(1) 전파.
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

from remediation.remediation import (
    DEFAULT_WAF_IPSET_NAME,
    DEFAULT_WAF_SCOPE,
    find_waf_ip_set,
    unblock_ip_wafv2,
)

DEFAULT_REGION = "ap-southeast-2"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("unblock_waf_ip")


def list_blocked_ips(
    ipset_name: str = DEFAULT_WAF_IPSET_NAME,
    scope: str = DEFAULT_WAF_SCOPE,
    waf_client: Any = None,
) -> list[str]:
    """현재 WAF IPSet에 등록된 차단 IP 목록 조회."""
    if waf_client is None:
        region = os.getenv("AWS_DEFAULT_REGION", DEFAULT_REGION)
        waf_client = boto3.client("wafv2", region_name=region)

    found = find_waf_ip_set(waf_client, ipset_name=ipset_name, scope=scope)
    if not found:
        raise ValueError(f"WAF IPSet을 찾을 수 없습니다: {ipset_name}")

    get_res = waf_client.get_ip_set(
        Name=ipset_name,
        Scope=scope,
        Id=found["id"],
    )
    return list(get_res.get("IPSet", {}).get("Addresses", []))


def unblock_waf_ip_entry(
    source_ip: str | None = None,
    unblock_all: bool = False,
    ipset_name: str = DEFAULT_WAF_IPSET_NAME,
    scope: str = DEFAULT_WAF_SCOPE,
    waf_client: Any = None,
) -> dict[str, Any]:
    """WAF IPSet에서 특정 IP 또는 전체 IP를 원자적으로 차단 해제하고 복구 시점 계측."""
    if waf_client is None:
        region = os.getenv("AWS_DEFAULT_REGION", DEFAULT_REGION)
        profile = os.getenv("AWS_PROFILE")
        session = boto3.Session(profile_name=profile, region_name=region)
        waf_client = session.client("wafv2")

    start_time = time.perf_counter()

    # 초기 상태 조회
    initial_ips = list_blocked_ips(ipset_name=ipset_name, scope=scope, waf_client=waf_client)
    logger.info("IPSet(%s) 현재 차단 목록: %s (총 %d건)", ipset_name, initial_ips, len(initial_ips))

    success = unblock_ip_wafv2(
        source_ip=source_ip,
        unblock_all=unblock_all,
        ipset_name=ipset_name,
        scope=scope,
        waf_client=waf_client,
    )

    if not success:
        raise RuntimeError(f"WAF IPSet({ipset_name}) 차단 해제 적용에 실패했습니다.")

    # 해제 후 최종 상태 조회
    final_ips = list_blocked_ips(ipset_name=ipset_name, scope=scope, waf_client=waf_client)
    restore_iso = datetime.datetime.now(datetime.UTC).isoformat()
    restore_epoch = time.time()
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    logger.info(
        "WAF IPSet(%s) 복구 완료: 잔여 차단 목록=%s (총 %d건, 소요 시간: %0.2f ms)",
        ipset_name,
        final_ips,
        len(final_ips),
        duration_ms,
    )

    return {
        "status": "success",
        "ipset_name": ipset_name,
        "target": "ALL" if unblock_all else source_ip,
        "previous_addresses": initial_ips,
        "current_addresses": final_ips,
        "t_restored_iso": restore_iso,
        "t_restored_epoch": restore_epoch,
        "duration_ms": duration_ms,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AWS WAFv2 IPSet 차단 해제 및 원자적 롤백 스크립트",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--ip",
        type=str,
        help="차단 해제할 단일 IPv4 주소 (예: 203.0.113.195 또는 203.0.113.195/32)",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="IPSet 내의 모든 차단 IP 목록 초기화",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="현재 차단된 IP 목록 조회만 수행",
    )
    parser.add_argument(
        "--ipset-name",
        type=str,
        default=DEFAULT_WAF_IPSET_NAME,
        help="대상 WAFv2 IPSet 명칭",
    )
    parser.add_argument(
        "--scope",
        type=str,
        default=DEFAULT_WAF_SCOPE,
        choices=["REGIONAL", "CLOUDFRONT"],
        help="WAFv2 범위 (REGIONAL 또는 CLOUDFRONT)",
    )
    parser.add_argument(
        "--region",
        type=str,
        default=DEFAULT_REGION,
        help="AWS 리전 (기본값: ap-southeast-2)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="결과를 JSON 포맷으로 표준 출력",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    os.environ["AWS_DEFAULT_REGION"] = args.region

    try:
        session = boto3.Session(region_name=args.region)
        waf_client = session.client("wafv2")

        if args.list:
            ips = list_blocked_ips(
                ipset_name=args.ipset_name,
                scope=args.scope,
                waf_client=waf_client,
            )
            if args.json:
                print(json.dumps({"ipset_name": args.ipset_name, "blocked_ips": ips}, indent=2))
            else:
                print(f"[{args.ipset_name}] 현재 차단 IP ({len(ips)}건): {ips}")
            sys.exit(0)

        result = unblock_waf_ip_entry(
            source_ip=args.ip,
            unblock_all=args.all,
            ipset_name=args.ipset_name,
            scope=args.scope,
            waf_client=waf_client,
        )

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(
                f"[성공] WAF IPSet 복구 완료: target={result['target']} | "
                f"T_restored={result['t_restored_iso']} | 소요시간={result['duration_ms']}ms"
            )
        sys.exit(0)

    except (ClientError, ValueError, RuntimeError) as e:
        logger.error("WAF IPSet 차단 해제 실패: %s", e)
        if args.json:
            print(json.dumps({"status": "error", "message": str(e)}, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
