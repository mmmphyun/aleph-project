"""WAF IP 차단 해제 스크립트(scripts/unblock_waf_ip.py) 단위 테스트.

소유자: 클라우드 A (플랫폼 전담)

Why:
    scripts/unblock_waf_ip.py의 단일 IP 차단 해제, 전체 해제, 목록 조회,
    CLI 파싱 및 멱등성 거동이 프로덕션 규격에 맞게 동작하는지 확증함.
"""

from __future__ import annotations

from typing import Any

import boto3
import pytest
from scripts.unblock_waf_ip import list_blocked_ips, parse_args, unblock_waf_ip_entry


def test_unblock_waf_ip_entry_single_ip_unverified_traffic(mocked_waf_ipset: Any) -> None:
    """verify_url 미지정 시 IPSet 설정 갱신만 확인하고 T_restored는 확정하지 않는지 검증."""
    from remediation.remediation import block_ip_wafv2

    waf_client = boto3.client("wafv2", region_name="us-east-1")
    target_ip = "203.0.113.50"

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

    assert result["status"] == "api_updated"
    assert result["verification_status"] == "IPSet 설정 갱신 확인, 트래픽 복구 미검증"
    assert result["traffic_verified"] is False
    assert result["target"] == target_ip
    assert f"{target_ip}/32" in result["previous_addresses"]
    assert f"{target_ip}/32" not in result["current_addresses"]
    assert result["t_api_updated_iso"] is not None
    assert result["t_api_updated_epoch"] is not None
    assert result["t_restored_iso"] is None
    assert result["t_restored_epoch"] is None
    assert result["duration_ms"] >= 0


def test_unblock_waf_ip_entry_propagation_delay_then_restored(mocked_waf_ipset: Any) -> None:
    """전파 지연으로 요청이 403 차단되다가 200 응답 시에만 T_restored를 확정하는지 검증."""
    from remediation.remediation import block_ip_wafv2

    waf_client = boto3.client("wafv2", region_name="us-east-1")
    target_ip = "203.0.113.51"

    block_ip_wafv2(
        source_ip=target_ip,
        ipset_name=mocked_waf_ipset.ipset_name,
        ipset_id=mocked_waf_ipset.ipset_id,
        waf_client=waf_client,
    )

    probe_statuses = iter([403, 403, 200])
    fake_clock_val = [100.0]

    def fake_clock() -> float:
        return fake_clock_val[0]

    def fake_sleep(sec: float) -> None:
        fake_clock_val[0] += sec

    result = unblock_waf_ip_entry(
        source_ip=target_ip,
        unblock_all=False,
        ipset_name=mocked_waf_ipset.ipset_name,
        scope=mocked_waf_ipset.scope,
        waf_client=waf_client,
        verify_url="http://alb.example.com/",
        verify_timeout=10.0,
        poll_interval=1.5,
        probe_source_ip=target_ip,
        observed_source_ip=target_ip,
        http_probe_fn=lambda _url, _timeout: next(probe_statuses),
        sleep_fn=fake_sleep,
        clock_fn=fake_clock,
    )

    assert result["status"] == "restored"
    assert result["verification_status"] == "트래픽 복구 확인 완료"
    assert result["traffic_verified"] is True
    assert result["t_api_updated_iso"] is not None
    assert result["t_restored_iso"] is not None
    assert result["t_restored_epoch"] >= result["t_api_updated_epoch"]
    assert fake_clock_val[0] == 103.0


def test_unblock_waf_ip_entry_verify_timeout_raises_error(mocked_waf_ipset: Any) -> None:
    """복구 확인 시간 초과 시 복구 성공을 보고하지 않고 RuntimeError를 발생시키는지 검증."""
    from remediation.remediation import block_ip_wafv2

    waf_client = boto3.client("wafv2", region_name="us-east-1")
    target_ip = "203.0.113.52"

    block_ip_wafv2(
        source_ip=target_ip,
        ipset_name=mocked_waf_ipset.ipset_name,
        ipset_id=mocked_waf_ipset.ipset_id,
        waf_client=waf_client,
    )

    fake_clock_val = [0.0]

    def fake_clock() -> float:
        return fake_clock_val[0]

    def fake_sleep(sec: float) -> None:
        fake_clock_val[0] += sec

    with pytest.raises(RuntimeError, match="실제 트래픽 복구"):
        unblock_waf_ip_entry(
            source_ip=target_ip,
            unblock_all=False,
            ipset_name=mocked_waf_ipset.ipset_name,
            scope=mocked_waf_ipset.scope,
            waf_client=waf_client,
            verify_url="http://alb.example.com/",
            verify_timeout=3.0,
            poll_interval=1.0,
            probe_source_ip=target_ip,
            observed_source_ip=target_ip,
            http_probe_fn=lambda _url, _timeout: 403,
            sleep_fn=fake_sleep,
            clock_fn=fake_clock,
        )


def test_unblock_waf_ip_entry_missing_probe_source_ip_unverified(mocked_waf_ipset: Any) -> None:
    """verify_url 지정 시 observed_source_ip 미입력 시 200 응답이라도 T_restored 미확정 검증."""
    from remediation.remediation import block_ip_wafv2

    waf_client = boto3.client("wafv2", region_name="us-east-1")
    target_ip = "203.0.113.55"

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
        verify_url="http://alb.example.com/",
        probe_source_ip=None,
        observed_source_ip=None,
        http_probe_fn=lambda _url, _timeout: 200,
    )

    assert result["status"] == "api_updated"
    assert (
        result["verification_status"]
        == "IPSet 설정 갱신 확인, 트래픽 복구 미검증 (실제 출발지 관측 근거 부재)"
    )
    assert result["traffic_verified"] is False
    assert result["t_restored_iso"] is None
    assert result["t_restored_epoch"] is None
    assert result["t_api_updated_iso"] is not None


def test_unblock_waf_ip_entry_same_input_strings_different_observed_egress_unverified(
    mocked_waf_ipset: Any,
) -> None:
    """입력 IP 문자열은 같지만 실제 프로브 출발지는 다른 조건에서 T_restored 미확정 검증."""
    from remediation.remediation import block_ip_wafv2

    waf_client = boto3.client("wafv2", region_name="us-east-1")
    target_ip = "203.0.113.50"

    block_ip_wafv2(
        source_ip=target_ip,
        ipset_name=mocked_waf_ipset.ipset_name,
        ipset_id=mocked_waf_ipset.ipset_id,
        waf_client=waf_client,
    )

    # --ip 203.0.113.50 --probe-source-ip 203.0.113.50 입력이지만
    # 실제 관측된 Egress IP는 198.51.100.99
    result = unblock_waf_ip_entry(
        source_ip=target_ip,
        unblock_all=False,
        ipset_name=mocked_waf_ipset.ipset_name,
        scope=mocked_waf_ipset.scope,
        waf_client=waf_client,
        verify_url="http://alb.example.com/",
        probe_source_ip=target_ip,
        observed_source_ip="198.51.100.99",
        http_probe_fn=lambda _url, _timeout: 200,
    )

    assert result["status"] == "api_updated"
    assert (
        result["verification_status"]
        == "IPSet 설정 갱신 확인, 트래픽 복구 미검증 (실제 프로브 출발지 불일치)"
    )
    assert result["traffic_verified"] is False
    assert result["t_restored_iso"] is None
    assert result["t_restored_epoch"] is None
    assert result["t_api_updated_iso"] is not None


def test_unblock_waf_ip_entry_probe_source_ip_mismatch_raises(mocked_waf_ipset: Any) -> None:
    """해제 대상 IP와 프로브 출발지 IP 불일치 시 ValueError 발생 검증."""
    waf_client = boto3.client("wafv2", region_name="us-east-1")

    with pytest.raises(ValueError, match="일치하지 않아"):
        unblock_waf_ip_entry(
            source_ip="203.0.113.50",
            unblock_all=False,
            ipset_name=mocked_waf_ipset.ipset_name,
            scope=mocked_waf_ipset.scope,
            waf_client=waf_client,
            verify_url="http://alb.example.com/",
            probe_source_ip="198.51.100.99",
            http_probe_fn=lambda _url, _timeout: 200,
        )


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

    assert result["status"] == "api_updated"
    assert result["traffic_verified"] is False
    assert result["target"] == "ALL"
    assert result["current_addresses"] == []
    assert result["t_restored_iso"] is None


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
