# CloudShield 시나리오 2 통합 E2E 관통 테스트 슈트
# 소유자: 클라우드 A (플랫폼 전담)
"""시나리오 2 (Web L7 공격) 유형별 E2E 파이프라인 관통 및 자동 대응 기능 검증.

Why:
    CloudWatch Logs Subscription Filter를 통해 비동기 인입되는 Nginx 접근 로그 페이로드 디코딩부터
    DynamoDB 기반 2-버킷 슬라이딩 윈도우(WebAttackWindow) 누적, 보안 룰 평가(evaluate_web_rules),
    IncidentReport 변환, WAFv2 IPSet L7 원자적 차단, Slack Block Kit 상황 전파까지
    Web 공격 자동 방어 파이프라인의 종단 간(E2E) 무결성을 단일 체인으로 기능 검증함.
    (주: 실제 인프라의 10초 미만 SLA 측정은 Phase 4 실기기 실측 마일스톤에서 증빙함)

Constraints:
    - Pytest 환경의 --disable-socket 제약 준수를 위해 외부 통신은 moto 및 Mock으로 완전 격리함.
    - Web L7 공격(SQLi, 디렉터리 스캔 등)은 타깃 서버 가용성을 보존하기 위해 L4 격리가 아닌
      L7 WAF IP 차단(BLOCK_IP_ONLY)을 집행해야 함.
    - 단발성 시그니처 위협(SQL Injection)과 시계열 누적 위협(Directory Scanning)을 모두 검증해야 함.
    - 이미 차단된 IP에 대한 후속 요청 인입 시 불필요한 차단 API 중복 호출을 억제해야 함.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import boto3
from tests.conftest import MockEc2Target, MockWafTarget

from contracts.events import CloudWatchLogEvent, CloudWatchLogsPayload
from remediation.orchestrator import threat_orchestrator_handler
from remediation.web_window import WebAttackWindow


def _create_cw_nginx_payload(
    log_messages: list[str],
    instance_id: str,
    base_timestamp_ms: int = 1727524320000,
    start_idx: int = 0,
) -> dict[str, Any]:
    """CloudWatch Logs Nginx 접근 로그 압축 페이로드 생성 헬퍼.

    Why:
        CloudWatch Logs Subscription Filter에서 인입되는 Base64 Gzip 인코딩 페이로드를
        실제 AWS Lambda 런타임 환경과 동일하게 재현함.
    """
    events = [
        CloudWatchLogEvent(
            id=f"e2e-nginx-evt-{start_idx + idx}",
            timestamp=base_timestamp_ms + (idx * 1000),
            message=msg,
        )
        for idx, msg in enumerate(log_messages)
    ]
    payload = CloudWatchLogsPayload(
        messageType="DATA_MESSAGE",
        owner="123456789012",
        logGroup="/cloudshield/target/nginx-access-log",
        logStream=instance_id,
        subscriptionFilters=["CloudShield-Nginx-Access-Filter"],
        logEvents=events,
    )
    return {"awslogs": {"data": payload.to_awslogs_data()}}


def test_e2e_scenario2_web_path_traversal_pipeline(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """[시나리오 2-A] Web L7 즉시 차단 위협(Path Traversal) E2E 관통 대응 기능 검증.

    Why:
        Path Traversal과 같은 즉시 차단 위협 인입 시, 타깃 EC2 인스턴스의 L4 가용성을 유지하면서
        WAFv2 IPSet에 공격자 IP가 L7 차단 등록되고 Slack 전파가 집행됨을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    web_window = WebAttackWindow()

    attacker_ip = "198.51.100.220"
    instance_id = mocked_ec2_target.instance_id
    webhook_url = "https://hooks.slack.com/services/T000/B000/E2E_TRAVERSAL_SUCCESS"

    # Path Traversal 공격 요청 로그 생성
    messages = [
        (
            f"{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "
            '"GET /../../etc/passwd HTTP/1.1" 404 150 "-" "curl/8.0" 0.005 "-"'
        )
    ]
    event = _create_cw_nginx_payload(messages, instance_id=instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True) as mock_slack:
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=web_window,
            slack_webhook_url=webhook_url,
        )

        # 1. 오케스트레이터 처리 결과 검증
        assert res["processed_events"] == 1
        assert "PATH_TRAVERSAL" in res["threats_detected"]
        assert len(res["incidents"]) == 1
        assert res["incidents"][0]["action_required"] in ("BLOCK_IP_ONLY", "BLOCK_WAF")
        assert res["incidents"][0]["source_ip"] == attacker_ip
        assert len(res["remediation_results"]) == 1
        assert res["remediation_results"][0]["waf_blocked"] is True
        assert res["slack_notified"] is True
        mock_slack.assert_called_once()

        # 2. AWS WAFv2 IPSet 상태 단언 (L7 차단 등록 확인)
        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set["IPSet"]["Addresses"]

        # 3. 타깃 EC2 보안 그룹 보존 검증 (L4 격리가 아닌 L7 IP 차단이어야 하므로 SG 미변경)
        instance_desc = ec2_client.describe_instances(InstanceIds=[instance_id])
        current_sgs = [
            sg["GroupId"]
            for sg in instance_desc["Reservations"][0]["Instances"][0]["SecurityGroups"]
        ]
        assert mocked_ec2_target.normal_sg_id in current_sgs
        assert mocked_ec2_target.quarantine_sg_id not in current_sgs


def test_e2e_scenario2_web_directory_scanning_split_batch_pipeline(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """[시나리오 2-B] Web L7 누적성 위협(디렉터리 스캔) 분할 배치 슬라이딩 윈도우 E2E 관통 검증.

    Why:
        CloudWatch Logs 버퍼링으로 인해 짧은 간격(5초) 내 발생한 스캔 요청이
        복수 Lambda 호출(배치 1: 3개, 배치 2: 2개)로 분할 인입되더라도,
        DynamoDB 기반 WebAttackWindow를 통해 상태가 누적 보존되어 임계치(5개) 도달 즉시
        WAFv2 차단이 집행됨을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    # 무상태 Lambda 런타임 간 인메모리 프로세스 공유를 배제하고
    # 오직 DynamoDB 영속화 계층을 통해서만 슬라이딩 윈도우가 복원·누적됨을 검증
    runtime_window_1 = WebAttackWindow()
    runtime_window_2 = WebAttackWindow()

    attacker_ip = "198.51.100.221"
    instance_id = mocked_ec2_target.instance_id
    webhook_url = "https://hooks.slack.com/services/T000/B000/E2E_SCAN_SUCCESS"

    scan_paths = ["/admin", "/login", "/dashboard", "/api", "/backup"]
    statuses = [401, 403, 404, 200, 302]
    all_messages = [
        (
            f'{attacker_ip} - - [28/Sep/2026:11:52:0{i} +0000] "GET {path} HTTP/1.1" '
            f'{status} 150 "-" "gobuster/3.1" 0.002 "-"'
        )
        for i, (path, status) in enumerate(zip(scan_paths, statuses, strict=True))
    ]

    # 배치 1: 3개 요청 인입 (임계치 5개 미달 -> 미차단)
    event_batch1 = _create_cw_nginx_payload(
        all_messages[:3],
        instance_id=instance_id,
        base_timestamp_ms=1727524320000,
        start_idx=0,
    )

    with patch("remediation.orchestrator.send_slack_alert", return_value=True) as mock_slack:
        res1 = threat_orchestrator_handler(
            event=event_batch1,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=runtime_window_1,
            slack_webhook_url=webhook_url,
        )

        assert res1["processed_events"] == 3
        assert res1["threats_detected"] == []
        assert res1["remediation_results"] == []
        assert res1["slack_notified"] is False
        mock_slack.assert_not_called()

        ip_set_1 = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" not in ip_set_1["IPSet"]["Addresses"]

        # 배치 2: 후속 2개 요청 인입 (독립 런타임 객체 주입 -> DynamoDB 누적 기반 차단 집행)
        event_batch2 = _create_cw_nginx_payload(
            all_messages[3:],
            instance_id=instance_id,
            base_timestamp_ms=1727524323000,
            start_idx=3,
        )

        res2 = threat_orchestrator_handler(
            event=event_batch2,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=runtime_window_2,
            slack_webhook_url=webhook_url,
        )

        assert res2["processed_events"] == 2
        assert "WEB_DIRECTORY_SCANNING" in res2["threats_detected"]
        assert len(res2["remediation_results"]) == 1
        assert res2["remediation_results"][0]["waf_blocked"] is True
        assert res2["slack_notified"] is True
        mock_slack.assert_called_once()

        ip_set_2 = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{attacker_ip}/32" in ip_set_2["IPSet"]["Addresses"]


def test_e2e_scenario2_normal_web_traffic_pipeline(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """[시나리오 2-C] 정상 웹 트래픽 인입 시 서비스 가용성 보존 검증.

    Why:
        일반 사용자의 합법적인 웹 요청에 대해 오탐(False Positive)으로 인한 WAF 차단이나
        Slack 알림 오발송이 발생하지 않고 원활한 서비스가 유지됨을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    web_window = WebAttackWindow()

    client_ip = "198.51.100.222"
    instance_id = mocked_ec2_target.instance_id

    messages = [
        (
            f'{client_ip} - - [28/Sep/2026:11:52:00 +0000] "GET /health HTTP/1.1" '
            '200 15 "-" "curl/8.0" 0.001 "-"'
        ),
        (
            f'{client_ip} - - [28/Sep/2026:11:52:01 +0000] "GET /index.html HTTP/1.1" '
            '200 1024 "-" "Mozilla/5.0" 0.003 "-"'
        ),
    ]
    event = _create_cw_nginx_payload(messages, instance_id=instance_id)

    with patch("remediation.orchestrator.send_slack_alert") as mock_slack:
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=web_window,
            slack_webhook_url="https://hooks.slack.com/services/T000/B000/NORMAL",
        )

        assert res["processed_events"] == 2
        assert res["threats_detected"] == []
        assert res["remediation_results"] == []
        assert res["slack_notified"] is False
        mock_slack.assert_not_called()

        ip_set = waf_client.get_ip_set(
            Name=mocked_waf_ipset.ipset_name,
            Scope=mocked_waf_ipset.scope,
            Id=mocked_waf_ipset.ipset_id,
        )
        assert f"{client_ip}/32" not in ip_set["IPSet"]["Addresses"]


def test_e2e_scenario2_idempotent_web_remediation_after_blocking(
    mocked_dynamodb_table: Any,
    mocked_ec2_target: MockEc2Target,
    mocked_waf_ipset: MockWafTarget,
) -> None:
    """[시나리오 2-D] 이미 차단된 공격자 IP의 추가 요청 인입 시 멱등성 및 단축 평가 검증.

    Why:
        동일 배치 내에서 이미 차단 집행된 공격자 IP의 후속 요청에 대해
        불필요한 WAF 차단 API 중복 호출을 억제(Short-circuit)하여 Quota 및 지연을 절감함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    waf_client = boto3.client("wafv2", region_name="us-east-1")
    web_window = WebAttackWindow()

    attacker_ip = "198.51.100.223"
    instance_id = mocked_ec2_target.instance_id

    # 동일 배치에 2개의 연속 민감 파일 탐색(SENSITIVE_FILE_PROBING) 인입
    messages = [
        (
            f"{attacker_ip} - - [28/Sep/2026:11:52:00 +0000] "
            '"GET /.env HTTP/1.1" 404 150 "-" "curl/8.0" 0.005 "-"'
        ),
        (
            f"{attacker_ip} - - [28/Sep/2026:11:52:01 +0000] "
            '"GET /.env.bak HTTP/1.1" 404 150 "-" "curl/8.0" 0.005 "-"'
        ),
    ]
    event = _create_cw_nginx_payload(messages, instance_id=instance_id)

    with patch("remediation.orchestrator.send_slack_alert", return_value=True) as mock_slack:
        res = threat_orchestrator_handler(
            event=event,
            ec2_client=ec2_client,
            waf_client=waf_client,
            web_window=web_window,
            slack_webhook_url="https://hooks.slack.com/services/T000/B000/IDEMPOTENT",
        )

        # 첫 번째 요청에서 차단 완료 후, 두 번째 요청은 blocked_ips 가드로 인해 중복 차단 생략
        assert res["processed_events"] == 2
        assert len(res["threats_detected"]) == 1
        assert len(res["remediation_results"]) == 1
        assert res["remediation_results"][0]["waf_blocked"] is True
        mock_slack.assert_called_once()
