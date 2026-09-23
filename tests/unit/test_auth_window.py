# CloudShield 단위 테스트: DynamoDB 기반 분할 배치 인증 실패 누적 윈도우
# 소유자: 클라우드 A 담당
"""이슈 #21: Lambda 배치 간 인증 실패 집계 보존 및 원자적 L4 격리 단위 테스트.

Why:
    CloudWatch Logs Subscription Filter가 5초 내 인증 실패 5건을 복수의 Lambda 호출
    (예: 3건 + 2건)로 분할 전달하더라도, DynamoDB 원자적 카운터(AuthFailureWindow)를 통해
    5분 슬라이딩 윈도우 내 누적 횟수를 정확히 판정하여 SSH_BRUTE_FORCE를 누락 없이 차단함을 검증함.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import MagicMock, patch

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


def test_concurrent_record_failure_race_condition(
    mocked_dynamodb_table: Any,
) -> None:
    """동시에 여러 요청이 빈 윈도우에 인입되더라도
    누적 카운터 및 계정 집합이 유실되지 않음을 검증.
    """
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )
    source_ip = "198.51.100.77"
    target_user = "concurrent_user"
    num_threads = 5

    # 1. 다중 스레드로 서로 다른 고유 계정 스프레잉 동시 인입
    def _call_record_spray(idx: int) -> dict[str, Any]:
        return auth_window.record_failure(
            source_ip=source_ip,
            username=f"user_{idx}",
            count=1,
        )

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(_call_record_spray, i) for i in range(num_threads)]
        for f in futures:
            f.result()

    spray_key = auth_window._get_spray_key(source_ip)
    spray_item = mocked_dynamodb_table.get_item(
        Key={"target_key": spray_key}, ConsistentRead=True
    ).get("Item", {})
    usernames = set(spray_item.get("usernames", set()))
    assert len(usernames) == num_threads

    # 2. 동일 계정에 대한 다중 스레드 무차별 대입 카운터 동시 인입 (Lost Update 방어 검증)
    def _call_record_same_user(_: int) -> dict[str, Any]:
        return auth_window.record_failure(
            source_ip=source_ip,
            username=target_user,
            count=1,
        )

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures2 = [executor.submit(_call_record_same_user, i) for i in range(num_threads)]
        for f in futures2:
            f.result()

    bf_key = auth_window._get_bf_key(source_ip, target_user)
    bf_item = mocked_dynamodb_table.get_item(Key={"target_key": bf_key}, ConsistentRead=True).get(
        "Item", {}
    )
    assert int(bf_item.get("failure_count", 0)) == num_threads


def test_check_threat_uses_consistent_read(
    mocked_dynamodb_table: Any,
) -> None:
    """check_threat 호출 시 get_item에 ConsistentRead=True가 강제되는지 검증."""
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )
    original_get_item = auth_window._table.get_item
    mock_get_item = MagicMock(side_effect=original_get_item)
    auth_window._table.get_item = mock_get_item

    auth_window.check_threat(source_ip="198.51.100.88", username="victim")

    assert mock_get_item.call_count >= 1
    for call_args in mock_get_item.call_args_list:
        assert call_args.kwargs.get("ConsistentRead") is True


def test_remediation_failure_allows_retry_on_next_batch(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """차단 조치 실패 시 quarantined 마킹이 생략되어 다음 배치에서 재시도됨을 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )
    attacker_ip = "203.0.113.99"
    user = "sysadmin"
    target_instance_id = mocked_ec2_target.instance_id

    # 5건 실패 로그 이벤트 (임계치 도달)
    msgs = [
        (
            f"Sep 04 15:01:0{i} target-ec2 sshd[2110{i}]: Failed password for "
            f"{user} from {attacker_ip} port 4120{i} ssh2"
        )
        for i in range(5)
    ]
    event = _create_cw_event(msgs, instance_id=target_instance_id)

    # 1. apply_remediation이 실패(quarantine_applied=False)를 반환하도록 패치
    with patch(
        "remediation.orchestrator.apply_remediation",
        return_value={"waf_blocked": False, "quarantine_applied": False, "iam_revoked": False},
    ) as mock_remediate:
        res1 = threat_orchestrator_handler(
            event=event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
        )
        assert len(res1["threats_detected"]) == 1
        assert mock_remediate.call_count == 1

    # 조치 실패로 인해 DynamoDB 상태 테이블에 quarantined가 False로 유지되어야 함
    bf_key = auth_window._get_bf_key(attacker_ip, user)
    item = mocked_dynamodb_table.get_item(Key={"target_key": bf_key}, ConsistentRead=True).get(
        "Item", {}
    )
    assert bool(item.get("quarantined", False)) is False

    # 2. 후속 6번째 실패 이벤트 인입
    msg_retry = [
        (
            f"Sep 04 15:01:06 target-ec2 sshd[21106]: Failed password for "
            f"{user} from {attacker_ip} port 41206 ssh2"
        )
    ]
    event_retry = _create_cw_event(msg_retry, instance_id=target_instance_id)

    # 이번에는 모의 AWS 클라이언트와 함께 정상 실행되어 L4 격리 및 WAF 차단 성공
    res2 = threat_orchestrator_handler(
        event=event_retry,
        auth_window=auth_window,
        ec2_client=ec2_client,
        waf_client=waf_client,
    )
    # 이전 실패로 인해 여전히 미격리 상태이므로 재탐지 및 재시도 성공
    assert "SSH_BRUTE_FORCE" in res2["threats_detected"]
    assert len(res2["remediation_results"]) == 1
    assert res2["remediation_results"][0]["quarantine_applied"] is True
    assert res2["remediation_results"][0]["waf_blocked"] is True

    # 성공 후에는 정상적으로 quarantined=True 마킹 확인
    item_after = mocked_dynamodb_table.get_item(
        Key={"target_key": bf_key}, ConsistentRead=True
    ).get("Item", {})
    assert item_after.get("quarantined") is True


def test_boundary_split_detection_accuracy(
    mocked_dynamodb_table: Any,
) -> None:
    """300초 윈도우 경계면(298초 2건, 302초 3건) 분할 인입 시
    타임스탬프 슬라이딩 윈도우에 의해 SSH_BRUTE_FORCE 탐지 성공 검증.

    Why:
        고정 텀블링 윈도우(대안 B)는 300초 경계면에서 2건과 3건으로 분할될 때
        각 버킷이 임계치(5회)에 미달하여 탐지에 100% 실패하는 Split-Brain 문제가 발생함.
        2-버킷 타임스탬프 슬라이딩 윈도우는 개별 이벤트 발생 시각을 보존하여
        경계면 분할 시에도 최근 300초 유효 구간 내 5회를 누락 없이 정확하게 탐지함을 검증함.
    """
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )
    source_ip = "198.51.100.123"
    username = "boundary_user"

    # 직전 버킷(298초) 2건 인입
    auth_window.record_failure(
        source_ip=source_ip, username=username, timestamp_epoch=298.0, count=2
    )
    # 현재 버킷(302초) 3건 인입
    auth_window.record_failure(
        source_ip=source_ip, username=username, timestamp_epoch=302.0, count=3
    )

    # 302초 시점 위협 판정 -> 유효 구간(t >= 2) 내 총 5건으로 SSH_BRUTE_FORCE 정상 탐지 확인
    is_threat, rule_name, target_key = auth_window.check_threat(
        source_ip=source_ip, username=username, timestamp_epoch=302.0
    )
    assert is_threat is True
    assert rule_name == "SSH_BRUTE_FORCE"
    assert target_key == auth_window._get_bf_key(source_ip, username, timestamp_epoch=302.0)


def test_boundary_split_password_spraying_accuracy(
    mocked_dynamodb_table: Any,
) -> None:
    """300초 윈도우 경계면(298초 user1, 302초 user2) 분할 인입 시
    SSH_PASSWORD_SPRAYING 탐지 성공 검증.

    Why:
        경계면 전후로 서로 다른 고유 계정이 인입되더라도 타임스탬프 필터링을 통해
        300초 구간 내 고유 계정 임계치(2개)를 충족하여 스프레잉을 탐지함을 검증함.
    """
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )
    source_ip = "198.51.100.124"

    # 직전 버킷(299초) user1 인입
    auth_window.record_failure(
        source_ip=source_ip, username="spray_user1", timestamp_epoch=299.0, count=1
    )
    # 현재 버킷(301초) user2 인입
    auth_window.record_failure(
        source_ip=source_ip, username="spray_user2", timestamp_epoch=301.0, count=1
    )

    # 301초 시점 위협 판정 -> 유효 구간(t >= 1) 내 user1, user2 고유 계정 2개 충족 탐지 확인
    is_threat, rule_name, target_key = auth_window.check_threat(
        source_ip=source_ip, username="spray_user2", timestamp_epoch=301.0
    )
    assert is_threat is True
    assert rule_name == "SSH_PASSWORD_SPRAYING"
    assert target_key == auth_window._get_spray_key(source_ip, timestamp_epoch=301.0)


def test_sliding_window_reviewer_edge_cases_fixed(
    mocked_dynamodb_table: Any,
) -> None:
    """PR #78 코드 리뷰(RockCandy444) 지적 4대 엣지 케이스 회귀 검증.

    Why:
        단순 정수 카운터 기반 시간 감쇠 방식은 비균등 버스트 트래픽에서 탐지 누락 2건,
        유효 시간 만료 트래픽에서 오탐 2건이 발생하는 중대한 결함이 존재했음.
        타임스탬프 슬라이딩 윈도우 전환을 통해 해당 4가지 사례가 모두 결함 없이
        정확하게 탐지(또는 차단 억제)됨을 검증함.
    """
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    # Case 1: [누락 방지] t=299에 4회, t=450에 1회 (151초 내 5회 집중 공격) -> 탐지
    ip_case1 = "198.51.100.1"
    auth_window.record_failure(source_ip=ip_case1, username="user1", timestamp_epoch=299.0, count=4)
    auth_window.record_failure(source_ip=ip_case1, username="user1", timestamp_epoch=450.0, count=1)
    is_threat1, rule1, _ = auth_window.check_threat(
        source_ip=ip_case1, username="user1", timestamp_epoch=450.0
    )
    assert is_threat1 is True
    assert rule1 == "SSH_BRUTE_FORCE"

    # Case 2: [누락 방지] t=299에 userA, t=451에 userB (152초 내 2계정 스프레잉) -> 탐지
    ip_case2 = "198.51.100.2"
    auth_window.record_failure(source_ip=ip_case2, username="userA", timestamp_epoch=299.0, count=1)
    auth_window.record_failure(source_ip=ip_case2, username="userB", timestamp_epoch=451.0, count=1)
    is_threat2, rule2, _ = auth_window.check_threat(
        source_ip=ip_case2, username="userB", timestamp_epoch=451.0
    )
    assert is_threat2 is True
    assert rule2 == "SSH_PASSWORD_SPRAYING"

    # Case 3: [오탐 방지] t=1에 4회, t=302에 1회 (301초 간격, 최근 300초엔 1회뿐) -> 미탐지
    ip_case3 = "198.51.100.3"
    auth_window.record_failure(source_ip=ip_case3, username="user1", timestamp_epoch=1.0, count=4)
    auth_window.record_failure(source_ip=ip_case3, username="user1", timestamp_epoch=302.0, count=1)
    is_threat3, rule3, _ = auth_window.check_threat(
        source_ip=ip_case3, username="user1", timestamp_epoch=302.0
    )
    assert is_threat3 is False
    assert rule3 is None

    # Case 4: [오탐 방지] t=1에 userA, t=302에 userB (301초 간격, 최근 300초엔 1개뿐) -> 미탐지
    ip_case4 = "198.51.100.4"
    auth_window.record_failure(source_ip=ip_case4, username="userA", timestamp_epoch=1.0, count=1)
    auth_window.record_failure(source_ip=ip_case4, username="userB", timestamp_epoch=302.0, count=1)
    is_threat4, rule4, _ = auth_window.check_threat(
        source_ip=ip_case4, username="userB", timestamp_epoch=302.0
    )
    assert is_threat4 is False
    assert rule4 is None
