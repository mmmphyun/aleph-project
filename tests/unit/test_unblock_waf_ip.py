"""WAF IP 차단 해제 스크립트(scripts/unblock_waf_ip.py) 단위 테스트.

소유자: 클라우드 A (플랫폼 전담)

Why:
    scripts/unblock_waf_ip.py의 단일 IP 차단 해제, 전체 해제, 목록 조회,
    CLI 파싱 및 멱등성 거동이 프로덕션 규격에 맞게 동작하는지 확증함.
"""

from __future__ import annotations

from typing import Any

import boto3
from scripts.unblock_waf_ip import list_blocked_ips, parse_args, unblock_waf_ip_entry


def test_unblock_waf_ip_entry_single_ip(mocked_waf_ipset: Any) -> None:
    """unblock_waf_ip_entry를 통한 단일 IP 해제 및 T_restored 반환 검증."""
    from remediation.remediation import block_ip_wafv2

    waf_client = boto3.client("wafv2", region_name="us-east-1")
    target_ip = "203.0.113.50"

    # 차단 선행
    block_ip_wafv2(
        source_ip=target_ip,
        ipset_name=mocked_waf_ipset.ipset_name,
        ipset_id=mocked_waf_ipset.ipset_id,
        waf_client=waf_client,
    )

    result = unblock_waf_ip_entry(
        source_ip=target_ip,
        unblock_all=False,
        ipset_name=mocked_waf_ipset.ipset_name,
        scope=mocked_waf_ipset.scope,
        waf_client=waf_client,
    )

    assert result["status"] == "success"
    assert result["target"] == target_ip
    assert f"{target_ip}/32" in result["previous_addresses"]
    assert f"{target_ip}/32" not in result["current_addresses"]
    assert "t_restored_iso" in result
    assert "t_restored_epoch" in result
    assert result["duration_ms"] >= 0


def test_unblock_waf_ip_entry_all(mocked_waf_ipset: Any) -> None:
    """unblock_waf_ip_entry unblock_all=True 일괄 초기화 검증."""
    from remediation.remediation import block_ip_wafv2

    waf_client = boto3.client("wafv2", region_name="us-east-1")
    block_ip_wafv2(
        source_ip="203.0.113.1",
        ipset_name=mocked_waf_ipset.ipset_name,
        ipset_id=mocked_waf_ipset.ipset_id,
        waf_client=waf_client,
    )

    result = unblock_waf_ip_entry(
        unblock_all=True,
        ipset_name=mocked_waf_ipset.ipset_name,
        scope=mocked_waf_ipset.scope,
        waf_client=waf_client,
    )

    assert result["status"] == "success"
    assert result["target"] == "ALL"
    assert result["current_addresses"] == []


def test_list_blocked_ips(mocked_waf_ipset: Any) -> None:
    """list_blocked_ips 조회 함수 정상 작동 검증."""
    from remediation.remediation import block_ip_wafv2

    waf_client = boto3.client("wafv2", region_name="us-east-1")
    test_ip = "203.0.113.99"
    block_ip_wafv2(
        source_ip=test_ip,
        ipset_name=mocked_waf_ipset.ipset_name,
        ipset_id=mocked_waf_ipset.ipset_id,
        waf_client=waf_client,
    )

    ips = list_blocked_ips(
        ipset_name=mocked_waf_ipset.ipset_name,
        scope=mocked_waf_ipset.scope,
        waf_client=waf_client,
    )
    assert f"{test_ip}/32" in ips


def test_parse_args_mutual_exclusion(monkeypatch: Any) -> None:
    """CLI 인자 파싱 상호 배타성 검증 (--ip, --all, --list)."""
    import sys

    monkeypatch.setattr(sys, "argv", ["unblock_waf_ip.py", "--ip", "1.2.3.4"])
    args = parse_args()
    assert args.ip == "1.2.3.4"
    assert args.all is False
    assert args.list is False

    monkeypatch.setattr(sys, "argv", ["unblock_waf_ip.py", "--all"])
    args_all = parse_args()
    assert args_all.all is True
    assert args_all.ip is None

    monkeypatch.setattr(sys, "argv", ["unblock_waf_ip.py", "--list"])
    args_list = parse_args()
    assert args_list.list is True
