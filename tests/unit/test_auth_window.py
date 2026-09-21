# CloudShield 단위 테스트: DynamoDB 기반 분할 배치 인증 실패 누적 윈도우
# 소유자: 클라우드 A 담당
"""이슈 #21: Lambda 배치 간 인증 실패 집계 보존 및 원자적 L4 격리 단위 테스트.

Why:
    CloudWatch Logs Subscription Filter가 5초 내 인증 실패 5건을 복수의 Lambda 호출
    (예: 3건 + 2건)로 분할 전달하더라도, DynamoDB 원자적 카운터(AuthFailureWindow)를 통해
    5분 슬라이딩 윈도우 내 누적 횟수를 정확히 판정하여 SSH_BRUTE_FORCE를 누락 없이 차단함을 검증함.
"""

from __future__ import annotations

from typing import Any

import boto3

from conftest import MockEc2Target, MockWafTarget
from contracts.events import CloudWatchLogEvent, CloudWatchLogsPayload
from remediation.auth_window import AuthFailureWindow
from remediation.orchestrator import threat_orchestrator_handler


def _create_cw_event(
    log_messages: list[str],
    instance_id: str,
    base_timestamp_ms: int = 1725433265000,
) -> dict[str, dict[str, str]]:
    """테스트용 CloudWatch Logs 구독 필터 페이로드 딕셔너리 생성 헬퍼."""
    events = [
        CloudWatchLogEvent(
            id=f"evt-{i}",
            timestamp=base_timestamp_ms + (i * 1000),
            message=msg,
        )
        for i, msg in enumerate(log_messages)
    ]
    payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/auth-log",
        logStream=instance_id,
        subscriptionFilters=["CloudShield-FailedPassword-Filter"],
        logEvents=events,
    )
    return {"awslogs": {"data": payload.to_awslogs_data()}}


def test_split_batches_cumulative_ssh_brute_force(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """[이슈 #21 핵심 완료 기준 검증]

    서로 다른 Lambda 호출로 분리된 동일 IPㆍ계정 인증 실패 3건과 2건이
    5분 내 누적되면 SSH_BRUTE_FORCE가 탐지되고 L4 격리 및 WAF 차단이 발동됨을 검증.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    attacker_ip = "203.0.113.195"
    target_user = "admin"
    target_instance_id = mocked_ec2_target.instance_id

    # 배치 1: 3건 실패 로그 (임계치 5건 미달)
    batch1_messages = [
        (
            f"Sep 04 15:01:0{i} target-ec2 sshd[2110{i}]: Failed password for "
            f"{target_user} from {attacker_ip} port 4120{i} ssh2"
        )
        for i in range(1, 4)
    ]
    event1 = _create_cw_event(
        batch1_messages,
        instance_id=target_instance_id,
        base_timestamp_ms=1725433265000,
    )

    # 1차 Lambda 호출 실행
    res1 = threat_orchestrator_handler(
        event=event1,
        auth_window=auth_window,
        ec2_client=ec2_client,
        waf_client=waf_client,
    )

    # 1차 호출 검증: 3건 처리 완료되었으나 임계치 미달로 탐지 및 격리 없음
    assert res1["processed_events"] == 3
    assert res1["threats_detected"] == []
    assert res1["remediation_results"] == []

    # 대상 EC2 보안 그룹이 아직 Normal SG인지 확인
    desc1 = ec2_client.describe_instances(InstanceIds=[target_instance_id])
    sgs1 = [sg["GroupId"] for sg in desc1["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert sgs1 == [mocked_ec2_target.normal_sg_id]

    # 배치 2: 2건 실패 로그 (누적 5건 달성)
    batch2_messages = [
        (
            f"Sep 04 15:01:0{i} target-ec2 sshd[2110{i}]: Failed password for "
            f"{target_user} from {attacker_ip} port 4120{i} ssh2"
        )
        for i in range(4, 6)
    ]
    event2 = _create_cw_event(
        batch2_messages,
        instance_id=target_instance_id,
        base_timestamp_ms=1725433268000,
    )

    # 2차 Lambda 호출 실행
    res2 = threat_orchestrator_handler(
        event=event2,
        auth_window=auth_window,
        ec2_client=ec2_client,
        waf_client=waf_client,
    )

    # 2차 호출 검증: 누적 5건으로 SSH_BRUTE_FORCE 탐지 및 복합 차단 완료
    assert res2["processed_events"] == 2
    assert "SSH_BRUTE_FORCE" in res2["threats_detected"]
    assert len(res2["remediation_results"]) == 1

    remediation = res2["remediation_results"][0]
    assert remediation["quarantine_applied"] is True
    assert remediation["waf_blocked"] is True

    # 대상 EC2 보안 그룹이 Quarantine SG로 원자적 교체되었는지 확인
    desc2 = ec2_client.describe_instances(InstanceIds=[target_instance_id])
    sgs2 = [sg["GroupId"] for sg in desc2["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert sgs2 == [mocked_ec2_target.quarantine_sg_id]

    # WAF IPSet에 공격자 IP(/32)가 성공적으로 등록되었는지 확인
    ipset = waf_client.get_ip_set(
        Name=mocked_waf_ipset.ipset_name,
        Scope=mocked_waf_ipset.scope,
        Id=mocked_waf_ipset.ipset_id,
    )
    assert f"{attacker_ip}/32" in ipset["IPSet"]["Addresses"]


def test_auth_window_sliding_expiration_reset(
    mocked_dynamodb_table: Any,
) -> None:
    """5분(300초) 슬라이딩 윈도우 만료 시 카운터가 원자적으로 리셋되는지 검증."""
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )
    source_ip = "198.51.100.77"
    username = "root"

    # t0 시점에 3회 실패 기록
    t0 = 1000.0
    auth_window.record_failure(source_ip=source_ip, username=username, timestamp_epoch=t0, count=3)
    is_threat, _, _ = auth_window.check_threat(source_ip=source_ip, username=username)
    assert is_threat is False

    # 301초 경과 후(t0 + 301) 2회 실패 추가 기록 (기존 윈도우 만료 -> 리셋)
    t1 = t0 + 301.0
    res = auth_window.record_failure(
        source_ip=source_ip,
        username=username,
        timestamp_epoch=t1,
        count=2,
    )

    # 윈도우가 새로 시작되어 카운터가 2여야 하며, 합산 5회로 오탐되지 않아야 함
    assert res["bf_count"] == 2
    is_threat_after, _, _ = auth_window.check_threat(source_ip=source_ip, username=username)
    assert is_threat_after is False


def test_split_batches_cumulative_password_spraying(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """분할 배치로 인입된 서로 다른 2개 계정 실패 시 SSH_PASSWORD_SPRAYING 탐지 검증."""
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )
    attacker_ip = "203.0.113.200"
    target_instance_id = mocked_ec2_target.instance_id

    # 배치 1: user1에 대한 실패 1건
    msg1 = [
        (
            f"Sep 04 15:01:01 target-ec2 sshd[21101]: Failed password for user1 "
            f"from {attacker_ip} port 41201 ssh2"
        )
    ]
    event1 = _create_cw_event(
        msg1,
        instance_id=target_instance_id,
        base_timestamp_ms=1725433265000,
    )
    res1 = threat_orchestrator_handler(
        event=event1,
        auth_window=auth_window,
        waf_client=waf_client,
    )
    assert res1["threats_detected"] == []

    # 배치 2: user2에 대한 실패 1건 (고유 계정 2건 도달)
    msg2 = [
        (
            f"Sep 04 15:01:02 target-ec2 sshd[21102]: Failed password for user2 "
            f"from {attacker_ip} port 41202 ssh2"
        )
    ]
    event2 = _create_cw_event(
        msg2,
        instance_id=target_instance_id,
        base_timestamp_ms=1725433266000,
    )
    res2 = threat_orchestrator_handler(
        event=event2,
        auth_window=auth_window,
        waf_client=waf_client,
    )
    assert "SSH_PASSWORD_SPRAYING" in res2["threats_detected"]
    assert res2["remediation_results"][0]["waf_blocked"] is True

    # WAF IPSet에 차단 등록 확인
    ipset = waf_client.get_ip_set(
        Name=mocked_waf_ipset.ipset_name,
        Scope=mocked_waf_ipset.scope,
        Id=mocked_waf_ipset.ipset_id,
    )
    assert f"{attacker_ip}/32" in ipset["IPSet"]["Addresses"]


def test_remediation_idempotency_suppression(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """이미 격리 조치된 타깃에 대해 추가 실패 배치 인입 시 중복 차단이 억제되는지 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )
    attacker_ip = "203.0.113.250"
    user = "operator"
    target_instance_id = mocked_ec2_target.instance_id

    # 1. 5회 연속 실패로 최초 차단 발동
    valid_msgs = [
        (
            f"Sep 04 15:01:0{i} target-ec2 sshd[2110{i}]: Failed password for "
            f"{user} from {attacker_ip} port 4120{i} ssh2"
        )
        for i in range(5)
    ]
    event = _create_cw_event(valid_msgs, instance_id=target_instance_id)
    res = threat_orchestrator_handler(
        event=event,
        auth_window=auth_window,
        ec2_client=ec2_client,
        waf_client=waf_client,
    )
    assert len(res["threats_detected"]) == 1

    # 2. 동일 윈도우 내 추가 6번째 실패 발생
    msg_extra = [
        (
            f"Sep 04 15:01:06 target-ec2 sshd[21106]: Failed password for "
            f"{user} from {attacker_ip} port 41206 ssh2"
        )
    ]
    event_extra = _create_cw_event(msg_extra, instance_id=target_instance_id)
    res_extra = threat_orchestrator_handler(
        event=event_extra,
        auth_window=auth_window,
        ec2_client=ec2_client,
        waf_client=waf_client,
    )

    # 이미 quarantined=True 상태이므로 중복 격리 및 차단 액션 미발생
    assert res_extra["threats_detected"] == []
    assert res_extra["remediation_results"] == []
