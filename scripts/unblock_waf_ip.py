"""AWS WAFv2 IPSet 차단 해제 및 원자적 롤백 스크립트.

소유자: 클라우드 A (플랫폼 전담)

Why:
    시나리오 2(Web L7) 관통 대응 실측 완료 또는 오탐 발생 후,
    WAF IPSet(CloudShield-Block-IPSet)에 등록된 공격자 IP(/32)를 원자적으로 제거하고,
    제어 평면 설정 갱신 시각(T_api_updated)과 데이터 평면 실제 트래픽 복구 시각(T_restored)을
    엄격히 분리 계측하여 전파 지연(Propagation Delay) 중 허위 복구 보고를 원천 차단함.

Constraints:
    - Boto3 WAFv2 API를 사용하여 단일 IP(/32) 또는 전체 목록을 원자적 갱신.
    - 동시 수정 충돌(WAFOptimisticLockException) 시 최신 LockToken 기반 최대 3회 재시도.
    - Read-after-Write 재조회를 통해 물리적 주소 목록 및 상위 CIDR 잔류 여부를 검증.
    - 실제 트래픽 복구 시각(T_restored)은 --verify-url을 통해 제한 시간 내 HTTP 2xx/3xx 응답이
      확증된 경우에만 기록하며, 미검증 시 'IPSet 설정 갱신 확인, 트래픽 복구 미검증'으로 명시.

Side-effects / Edge-cases:
    - IPSet에 대상 IP 및 상위 CIDR이 이미 없으면 멱등(Idempotency) 성공 처리.
    - 트래픽 복구 확인 시간 초과(403 지속) 시 RuntimeError 발생 및 sys.exit(1) 전파.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import sys
import time
from collections.abc import Callable
from typing import Any

import boto3
from botocore.exceptions import ClientError

from remediation.remediation import (
    DEFAULT_WAF_IPSET_NAME,
    DEFAULT_WAF_POLL_INTERVAL,
    DEFAULT_WAF_SCOPE,
    DEFAULT_WAF_VERIFY_TIMEOUT,
    find_waf_ip_set,
    normalize_single_ipv4,
    unblock_ip_wafv2,
    verify_waf_traffic_restored,
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
    verify_url: str | None = None,
    verify_timeout: float = DEFAULT_WAF_VERIFY_TIMEOUT,
    poll_interval: float = DEFAULT_WAF_POLL_INTERVAL,
    probe_source_ip: str | None = None,
    http_probe_fn: Callable[[str, float], int] | None = None,
    sleep_fn: Callable[[float], None] | None = None,
    clock_fn: Callable[[], float] | None = None,
) -> dict[str, Any]:
    """WAF IPSet에서 차단 해제 후 API 갱신 시각과 실제 트래픽 복구 시각을 분리 계측."""
    should_verify_traffic = bool(verify_url)
    unverified_reason = ""

    if should_verify_traffic and not unblock_all and source_ip:
        if not probe_source_ip:
            should_verify_traffic = False
            unverified_reason = " (출발지 미확인)"
            logger.warning(
                "검증 대상 출발지 IP(probe_source_ip)가 미제공되어 실제 트래픽 복구(T_restored)를 "
                "확정할 수 없습니다. (IPSet 설정 갱신만 수행)"
            )
        else:
            target_host_ip = normalize_single_ipv4(source_ip)
            actual_probe_ip = normalize_single_ipv4(probe_source_ip)
            if target_host_ip != actual_probe_ip:
                raise ValueError(
                    f"트래픽 복구 검증 출발지 IP({actual_probe_ip})가 "
                    f"해제 대상 IP({target_host_ip})와 일치하지 않아 "
                    "T_restored를 확정할 수 없습니다."
                )

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

    # 제어 평면(Control Plane) 설정 갱신 최종 조회 및 시각 기록
    final_ips = list_blocked_ips(ipset_name=ipset_name, scope=scope, waf_client=waf_client)
    t_api_updated_iso = datetime.datetime.now(datetime.UTC).isoformat()
    t_api_updated_epoch = time.time()
    api_duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    if not should_verify_traffic:
        status_msg = f"IPSet 설정 갱신 확인, 트래픽 복구 미검증{unverified_reason}"
        logger.info(
            "WAF IPSet(%s) %s: 잔여 목록=%s (총 %d건, API 소요 시간: %0.2f ms)",
            ipset_name,
            status_msg,
            final_ips,
            len(final_ips),
            api_duration_ms,
        )
        return {
            "status": "api_updated",
            "verification_status": status_msg,
            "traffic_verified": False,
            "ipset_name": ipset_name,
            "target": "ALL" if unblock_all else source_ip,
            "previous_addresses": initial_ips,
            "current_addresses": final_ips,
            "t_api_updated_iso": t_api_updated_iso,
            "t_api_updated_epoch": t_api_updated_epoch,
            "t_restored_iso": None,
            "t_restored_epoch": None,
            "api_duration_ms": api_duration_ms,
            "duration_ms": api_duration_ms,
        }

    # 데이터 평면(Data Plane) 실제 트래픽 복구 폴링 검증
    is_restored = verify_waf_traffic_restored(
        verify_url=verify_url,
        timeout=verify_timeout,
        poll_interval=poll_interval,
        http_probe_fn=http_probe_fn,
        sleep_fn=sleep_fn,
        clock_fn=clock_fn,
    )
    if not is_restored:
        raise RuntimeError(
            f"WAF IPSet({ipset_name}) 설정은 갱신되었으나 제한 시간({verify_timeout}s) 내 "
            f"실제 트래픽 복구({verify_url})가 확인되지 않았습니다."
        )

    restore_iso = datetime.datetime.now(datetime.UTC).isoformat()
    restore_epoch = time.time()
    total_duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    logger.info(
        "WAF IPSet(%s) 트래픽 복구 확인 완료: 잔여 목록=%s (총 %d건, 총 소요 시간: %0.2f ms)",
        ipset_name,
        final_ips,
        len(final_ips),
        total_duration_ms,
    )

    return {
        "status": "restored",
        "verification_status": "트래픽 복구 확인 완료",
        "traffic_verified": True,
        "ipset_name": ipset_name,
        "target": "ALL" if unblock_all else source_ip,
        "previous_addresses": initial_ips,
        "current_addresses": final_ips,
        "t_api_updated_iso": t_api_updated_iso,
        "t_api_updated_epoch": t_api_updated_epoch,
        "t_restored_iso": restore_iso,
        "t_restored_epoch": restore_epoch,
        "api_duration_ms": api_duration_ms,
        "duration_ms": total_duration_ms,
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
        "--verify-url",
        type=str,
        default=None,
        help="실제 트래픽 복구 확인을 위한 대상 URL (미지정 시 제어 평면 설정 갱신만 확인)",
    )
    parser.add_argument(
        "--verify-timeout",
        type=float,
        default=DEFAULT_WAF_VERIFY_TIMEOUT,
        help="트래픽 복구 확인 최대 대기 시간(초)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=DEFAULT_WAF_POLL_INTERVAL,
        help="트래픽 복구 폴링 간격(초)",
    )
    parser.add_argument(
        "--probe-source-ip",
        type=str,
        default=None,
        help="프로브 요청 출발지 IPv4 (단일 IP 해제 시 대상 IP와 일치 여부 검증)",
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
            verify_url=args.verify_url,
            verify_timeout=args.verify_timeout,
            poll_interval=args.poll_interval,
            probe_source_ip=args.probe_source_ip,
        )

        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        elif result["traffic_verified"]:
            print(
                f"[성공] WAF 트래픽 복구 확인 완료: target={result['target']} | "
                f"T_api_updated={result['t_api_updated_iso']} | "
                f"T_restored={result['t_restored_iso']} | 소요시간={result['duration_ms']}ms"
            )
        else:
            print(
                f"[성공] IPSet 설정 갱신 확인, 트래픽 복구 미검증: target={result['target']} | "
                f"T_api_updated={result['t_api_updated_iso']} | "
                f"T_restored=None | API소요시간={result['api_duration_ms']}ms"
            )
        sys.exit(0)

    except (ClientError, ValueError, RuntimeError) as e:
        logger.error("WAF IPSet 차단 해제 실패: %s", e)
        if args.json:
            print(json.dumps({"status": "error", "message": str(e)}, indent=2, ensure_ascii=False))
        sys.exit(1)


if __name__ == "__main__":
    main()
