# CloudShield 시나리오 1 통합 E2E 관통 테스트 슈트
# 소유자: 클라우드 A (플랫폼 전담)
"""시나리오 1 (SSH 공격) 유형별 E2E 파이프라인 관통 및 10초 자동 대응 검증.

Why:
    CloudWatch Logs Subscription Filter 페이로드 디코딩부터 DynamoDB 윈도우 슬라이딩 집계,
    보안 매퍼(IncidentReport) 변환, Boto3 다중 계층 격리(L4 SG / L7 WAF), Slack 카드 알림까지
    개별 단위 모듈이 결합된 전체 방어 파이프라인의 종단 간(E2E) 무결성을 단일 체인으로 검증함.

Constraints:
    - Pytest 환경의 --disable-socket 제약 준수를 위해 외부 통신은 moto 및 Mock으로 격리함.
    - SSH Brute Force는 L4 격리 및 L7 차단(BLOCK_AND_QUARANTINE)을 완결해야 함.
    - SSH Password Spraying은 타깃 서버 가용성을 유지하며 공격자 IP만 L7 차단(BLOCK_IP_ONLY)해야 함.
    - Password Spraying 시 노출된 복수의 공격 대상 계정이 IncidentReport에 보존되어야 함.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import boto3
from tests.conftest import MockEc2Target, MockWafTarget

from contracts.events import CloudWatchLogEvent, CloudWatchLogsPayload
from contracts.incident import IncidentReport
from remediation.auth_window import AuthFailureWindow
from remediation.orchestrator import threat_orchestrator_handler
from reporter.slack_notifier import build_slack_payload


def _create_cw_auth_payload(
    log_messages: list[str],
    instance_id: str,
    base_timestamp_ms: int = 1725433265000,
) -> dict[str, Any]:
    """CloudWatch Logs 압축 페이로드 생성 헬퍼.

    Why:
        CloudWatch Logs Subscription Filter에서 인입되는 Base64 Gzip 인코딩 페이로드를
        실제 AWS Lambda 런타임 환경과 동일하게 재현함.
    """
    events = [
        CloudWatchLogEvent(
            id=f"e2e-evt-{idx}",
            timestamp=base_timestamp_ms + (idx * 1000),
            message=msg,
        )
        for idx, msg in enumerate(log_messages)
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


def test_e2e_scenario1_ssh_brute_force_pipeline(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """[시나리오 1-A] SSH Brute Force 단일 계정 집중 공격 E2E 관통 대응 검증.

    Why:
        단일 계정에 대한 5회 이상 인증 실패 시 10초 내에 타깃 EC2 인스턴스 L4 격리 및
        공격자 IP L7 WAF 차단, Slack 전파가 1회의 원자적 트랜잭션으로 집행됨을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    attacker_ip = "198.51.100.11"
    target_user = "root"
    instance_id = mocked_ec2_target.instance_id
    webhook_url = "https://hooks.slack.com/services/T000/B000/E2E_BF_SUCCESS"

    # 1. 5회 연속 실패 로그 생성 (Brute Force 임계치 도달)
    messages = [
        (
            f"Sep 04 15:00:0{i} target-server sshd[100{i}]: Failed password for "
            f"{target_user} from {attacker_ip} port 500{i} ssh2"
        )
        for i in range(1, 6)
    ]
    event = _create_cw_auth_payload(messages, instance_id=instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True) as mock_slack:
        res = threat_orchestrator_handler(
            event=event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url=webhook_url,
        )

        # A. 오케스트레이터 처리 지표 검증
        assert res["processed_events"] == 5
        assert res["threats_detected"] == ["SSH_BRUTE_FORCE"]
        assert res["slack_notified"] is True

        # B. 생성된 IncidentReport 계약 무결성 검증
        assert len(res["incidents"]) == 1
        incident_dict = res["incidents"][0]
        report = IncidentReport.model_validate(incident_dict)
        assert report.attack_type == "SSH Brute Force"
        assert report.mitre_id == "T1110.001"
        assert report.risk_level == "HIGH"
        assert report.source_ip == attacker_ip
        assert report.target_accounts == (target_user,)
        assert report.action_required == "BLOCK_AND_QUARANTINE"

        # C. Boto3 차단 결과 모델 검증
        assert len(res["remediation_results"]) == 1
        rem_res = res["remediation_results"][0]
        assert rem_res["quarantine_applied"] is True
        assert rem_res["waf_blocked"] is True

        # D. 실제 AWS 인프라(moto) 격리 상태 실측 검증
        # 1) EC2 Security Group이 격리 SG로 교체되었는지 확인
        desc_ec2 = ec2_client.describe_instances(InstanceIds=[instance_id])
        assigned_sgs = [
            sg["GroupId"] for sg in desc_ec2["Reservations"][0]["Instances"][0]["SecurityGroups"]
        ]
        assert assigned_sgs == [mocked_ec2_target.quarantine_sg_id]

        # 2) WAF IPSet에 공격자 IP/32가 차단 등록되었는지 확인
        desc_waf = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in desc_waf["IPSet"]["Addresses"]

        # E. Slack 알림 인자 및 Block Kit 렌더링 무결성 검증
        mock_slack.assert_called_once()
        slack_kwargs = mock_slack.call_args.kwargs
        assert slack_kwargs["webhook_url"] == webhook_url

        card_payload = build_slack_payload(report=report, remediation_result=rem_res)
        card_str = json.dumps(card_payload, ensure_ascii=False)
        assert attacker_ip in card_str
        assert "SSH Brute Force" in card_str
        assert target_user in card_str
        assert "격리 성공" in card_str

        # F. 멱등성 검증: 동일 공격 로그 2건 추가 인입 시 중복 차단 억제 확인
        extra_messages = [
            (
                f"Sep 04 15:00:1{i} target-server sshd[101{i}]: Failed password for "
                f"{target_user} from {attacker_ip} port 501{i} ssh2"
            )
            for i in range(1, 3)
        ]
        extra_event = _create_cw_auth_payload(extra_messages, instance_id=instance_id)
        res_idempotent = threat_orchestrator_handler(
            event=extra_event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url=webhook_url,
        )
        # 이미 격리 마킹되었으므로 추가 차단/인시던트 생성 0건
        assert res_idempotent["processed_events"] == 2
        assert res_idempotent["threats_detected"] == []
        assert res_idempotent["incidents"] == []
        assert res_idempotent["remediation_results"] == []


def test_e2e_scenario1_ssh_password_spraying_pipeline(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """[시나리오 1-B] SSH Password Spraying 다중 계정 분산 공격 E2E 관통 대응 검증.

    Why:
        동일 출발지 IP에서 2개 이상의 서로 다른 계정을 시도할 경우,
        서버를 격리하여 정상 서비스를 중단시키는 과잉 대응을 방지하고
        공격자 IP만 L7 WAF에서 차단(BLOCK_IP_ONLY)하며,
        공격 대상 고유 계정 목록이 누락 없이 IncidentReport에 보존됨을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    attacker_ip = "198.51.100.22"
    target_users = ["root", "admin", "ubuntu"]
    instance_id = mocked_ec2_target.instance_id
    webhook_url = "https://hooks.slack.com/services/T000/B000/E2E_SPRAY_SUCCESS"

    # 1. 3개 고유 계정에 대한 분산 실패 로그 생성 (Password Spraying 임계치 2개 초과)
    messages = [
        (
            f"Sep 04 15:05:0{i} target-server sshd[200{i}]: Failed password for "
            f"{user} from {attacker_ip} port 600{i} ssh2"
        )
        for i, user in enumerate(target_users, start=1)
    ]
    event = _create_cw_auth_payload(messages, instance_id=instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True) as mock_slack:
        res = threat_orchestrator_handler(
            event=event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url=webhook_url,
        )

        # A. 오케스트레이터 처리 지표 검증
        assert res["processed_events"] == 3
        assert res["threats_detected"] == ["SSH_PASSWORD_SPRAYING"]
        assert res["slack_notified"] is True

        # B. 생성된 IncidentReport 계약 및 계정 목록 충실도(Fidelity) 검증
        assert len(res["incidents"]) == 1
        incident_dict = res["incidents"][0]
        report = IncidentReport.model_validate(incident_dict)
        assert report.attack_type == "SSH Password Spraying"
        assert report.mitre_id == "T1110.003"
        assert report.risk_level == "MEDIUM"
        assert report.source_ip == attacker_ip
        assert report.action_required == "BLOCK_IP_ONLY"

        # [결함 수정 검증]: 단일 계정이 아닌 공격에 노출된 3개 계정 전체가 복원되어야 함
        assert set(report.target_accounts) == set(target_users)

        # C. Boto3 차단 결과 모델 검증
        assert len(res["remediation_results"]) == 1
        rem_res = res["remediation_results"][0]
        # 인스턴스 격리는 미실시(False), WAF IP 차단만 성공(True)
        assert rem_res["quarantine_applied"] is False
        assert rem_res["waf_blocked"] is True

        # D. 실제 AWS 인프라(moto) 상태 실측 검증
        # 1) EC2 Security Group은 격리되지 않고 정상 SG 유지 확인
        desc_ec2 = ec2_client.describe_instances(InstanceIds=[instance_id])
        assigned_sgs = [
            sg["GroupId"] for sg in desc_ec2["Reservations"][0]["Instances"][0]["SecurityGroups"]
        ]
        assert assigned_sgs == [mocked_ec2_target.normal_sg_id]

        # 2) WAF IPSet에는 공격자 IP/32가 차단 등록 확인
        desc_waf = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in desc_waf["IPSet"]["Addresses"]

        # E. Slack 알림 인자 및 Block Kit 렌더링 무결성 검증
        mock_slack.assert_called_once()
        card_payload = build_slack_payload(report=report, remediation_result=rem_res)
        card_str = json.dumps(card_payload, ensure_ascii=False)
        assert attacker_ip in card_str
        assert "SSH Password Spraying" in card_str
        assert "BLOCK_IP_ONLY" in card_str
        # 공격 대상 계정 목록이 Slack 카드에 모두 포맷팅되었는지 확인
        for u in target_users:
            assert u in card_str

        # F. 멱등성 검증: 추가 계정 분산 공격 인입 시 중복 차단 억제 확인
        extra_messages = [
            (
                f"Sep 04 15:05:10 target-server sshd[2010]: Failed password for "
                f"guest from {attacker_ip} port 6010 ssh2"
            )
        ]
        extra_event = _create_cw_auth_payload(extra_messages, instance_id=instance_id)
        res_idempotent = threat_orchestrator_handler(
            event=extra_event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url=webhook_url,
        )
        assert res_idempotent["processed_events"] == 1
        assert res_idempotent["threats_detected"] == []
        assert res_idempotent["incidents"] == []


def test_e2e_scenario1_split_batches_interleaved_brute_force(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """[시나리오 1-C] 2회 분할 배치 인입에 대한 슬라이딩 윈도우 누적 탐지 E2E 검증.

    Why:
        CloudWatch Subscription Filter 버퍼링에 의해 5회의 공격이 3회, 2회로
        서로 다른 Lambda 호출에 나뉘어 인입되더라도, DynamoDB 윈도우 원자적 누적을 통해
        2차 배치 인입 시점에 즉시 Brute Force를 탐지하고 격리함을 입증함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    attacker_ip = "198.51.100.33"
    target_user = "developer"
    instance_id = mocked_ec2_target.instance_id

    # 배치 1: 3건 인입 (임계치 5건 미달 -> 차단 없음)
    batch1_messages = [
        (
            f"Sep 04 15:10:0{i} target-server sshd[300{i}]: Failed password for "
            f"{target_user} from {attacker_ip} port 700{i} ssh2"
        )
        for i in range(1, 4)
    ]
    batch1_event = _create_cw_auth_payload(batch1_messages, instance_id=instance_id)

    res1 = threat_orchestrator_handler(
        event=batch1_event,
        auth_window=auth_window,
        ec2_client=ec2_client,
        waf_client=waf_client,
    )
    assert res1["processed_events"] == 3
    assert res1["threats_detected"] == []
    assert res1["incidents"] == []

    # 배치 2: 2건 추가 인입 (누적 5건 도달 -> Brute Force 트리거)
    batch2_messages = [
        (
            f"Sep 04 15:10:1{i} target-server sshd[301{i}]: Failed password for "
            f"{target_user} from {attacker_ip} port 701{i} ssh2"
        )
        for i in range(1, 3)
    ]
    batch2_event = _create_cw_auth_payload(batch2_messages, instance_id=instance_id)

    res2 = threat_orchestrator_handler(
        event=batch2_event,
        auth_window=auth_window,
        ec2_client=ec2_client,
        waf_client=waf_client,
    )
    assert res2["processed_events"] == 2
    assert res2["threats_detected"] == ["SSH_BRUTE_FORCE"]
    assert res2["remediation_results"][0]["quarantine_applied"] is True
    assert res2["remediation_results"][0]["waf_blocked"] is True

    # EC2가 격리 SG로 교체 완료되었는지 확인
    desc_ec2 = ec2_client.describe_instances(InstanceIds=[instance_id])
    assigned_sgs = [
        sg["GroupId"] for sg in desc_ec2["Reservations"][0]["Instances"][0]["SecurityGroups"]
    ]
    assert assigned_sgs == [mocked_ec2_target.quarantine_sg_id]


def test_e2e_scenario1_split_batches_interleaved_password_spraying(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """[시나리오 1-D] 2회 분할 배치 인입에 대한 Password Spraying 누적 계정 복원 E2E 검증.

    Why:
        Batch 1(admin 계정)과 Batch 2(guest 계정)가 시간차를 두고 인입되었을 때,
        Batch 2 처리 시점에 Batch 1의 과거 계정까지 합산된 {'admin', 'guest'}가
        IncidentReport.target_accounts에 완벽히 복원되는지 검증함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    attacker_ip = "198.51.100.44"
    instance_id = mocked_ec2_target.instance_id

    # 배치 1: admin 계정 1회 인입 (임계치 2개 계정 미달)
    batch1_messages = [
        (
            f"Sep 04 15:20:01 target-server sshd[4001]: Failed password for "
            f"admin from {attacker_ip} port 8001 ssh2"
        )
    ]
    batch1_event = _create_cw_auth_payload(batch1_messages, instance_id=instance_id)

    res1 = threat_orchestrator_handler(
        event=batch1_event,
        auth_window=auth_window,
        ec2_client=ec2_client,
        waf_client=waf_client,
    )
    assert res1["processed_events"] == 1
    assert res1["threats_detected"] == []

    # 배치 2: guest 계정 1회 인입 (누적 고유 계정 2개 도달 -> Password Spraying 트리거)
    batch2_messages = [
        (
            f"Sep 04 15:20:05 target-server sshd[4002]: Failed password for "
            f"guest from {attacker_ip} port 8002 ssh2"
        )
    ]
    batch2_event = _create_cw_auth_payload(batch2_messages, instance_id=instance_id)

    res2 = threat_orchestrator_handler(
        event=batch2_event,
        auth_window=auth_window,
        ec2_client=ec2_client,
        waf_client=waf_client,
    )
    assert res2["processed_events"] == 1
    assert res2["threats_detected"] == ["SSH_PASSWORD_SPRAYING"]
    assert res2["incidents"][0]["action_required"] == "BLOCK_IP_ONLY"

    # 누적된 계정 집합 검증 (과거 배치 계정과 현재 배치 계정의 합집합)
    assert set(res2["incidents"][0]["target_accounts"]) == {"admin", "guest"}
    assert res2["remediation_results"][0]["quarantine_applied"] is False
    assert res2["remediation_results"][0]["waf_blocked"] is True


def test_e2e_scenario1_slack_failure_fault_isolation(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """[시나리오 1-E] Slack Webhook 전송 장애 시 인프라 차단 트랜잭션 완전 격리 E2E 검증.

    Why:
        Slack 외부 통신망 장애(HTTP 500, Timeout, 네트워크 유실)가 발생하더라도
        선행 집행된 L4 SG 격리와 L7 WAF 차단, DynamoDB 멱등성 마킹 상태는 절대 롤백되지 않고
        안전하게 영속 유지됨을 입증함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    auth_window = AuthFailureWindow(
        table_name="CloudShield-AuthFailure-Window",
        window_seconds=300,
    )

    attacker_ip = "198.51.100.55"
    target_user = "root"
    instance_id = mocked_ec2_target.instance_id
    webhook_url = "https://hooks.slack.com/services/T000/B000/E2E_SLACK_ERROR"

    messages = [
        (
            f"Sep 04 15:30:0{i} target-server sshd[500{i}]: Failed password for "
            f"{target_user} from {attacker_ip} port 900{i} ssh2"
        )
        for i in range(1, 6)
    ]
    event = _create_cw_auth_payload(messages, instance_id=instance_id)

    # Slack 전송 도중 RuntimeException 발생 유도
    with patch(
        "remediation.orchestrator.send_slack_alert",
        side_effect=RuntimeError("Slack Webhook Gateway Timeout"),
    ):
        res = threat_orchestrator_handler(
            event=event,
            auth_window=auth_window,
            ec2_client=ec2_client,
            waf_client=waf_client,
            slack_webhook_url=webhook_url,
        )

        # Slack 통보는 실패했으나 핸들러는 예외 없이 안전 종료됨
        assert res["processed_events"] == 5
        assert res["threats_detected"] == ["SSH_BRUTE_FORCE"]
        assert res["slack_notified"] is False
        assert res["remediation_results"][0]["quarantine_applied"] is True
        assert res["remediation_results"][0]["waf_blocked"] is True

        # EC2 L4 격리 상태가 정상 유지되었는지 확인 (롤백 없음)
        desc_ec2 = ec2_client.describe_instances(InstanceIds=[instance_id])
        assigned_sgs = [
            sg["GroupId"] for sg in desc_ec2["Reservations"][0]["Instances"][0]["SecurityGroups"]
        ]
        assert assigned_sgs == [mocked_ec2_target.quarantine_sg_id]

        # WAF L7 차단 상태가 정상 유지되었는지 확인 (롤백 없음)
        desc_waf = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in desc_waf["IPSet"]["Addresses"]

        # DynamoDB 격리 완료 플래그 마킹 유지 확인
        threat_check = auth_window.check_threat(attacker_ip, target_user)
        assert threat_check.is_threat is False
