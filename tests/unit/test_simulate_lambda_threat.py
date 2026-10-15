# CloudShield 단위 테스트: 실인프라 모의 위협 주입 도구
# 소유자: 클라우드 A 담당
"""scripts/simulate_lambda_threat.py 단위 테스트."""

from __future__ import annotations

import base64
import gzip
import io
import json
from unittest.mock import MagicMock

import pytest
from scripts.simulate_lambda_threat import (
    DEFAULT_BASELINE_SG_ID,
    DEFAULT_FUNCTION_NAME,
    DEFAULT_INSTANCE_ID,
    DEFAULT_TEST_SOURCE_IP,
    build_mock_cw_logs_payload,
    parse_args,
    simulate_threat_and_verify,
)


def test_build_mock_cw_logs_payload() -> None:
    """모의 CloudWatch Logs Subscription Filter 페이로드 규격 검증.

    Why:
        Lambda 오케스트레이터 핸들러가 요구하는 표준 gzip 압축 및
        Base64 인코딩 형식을 정확히 준수하는지 검증함.
    """
    event = build_mock_cw_logs_payload(
        instance_id="i-test12345",
        source_ip="198.51.100.99",
        username="test_user",
        failure_count=5,
    )

    assert "awslogs" in event
    assert "data" in event["awslogs"]

    # Base64 디코딩 및 Gzip 압축 해제 검증
    raw_data = base64.b64decode(event["awslogs"]["data"])
    decompressed = gzip.decompress(raw_data).decode("utf-8")
    payload = json.loads(decompressed)

    assert payload["logGroup"] == "/cloudshield/target/auth-log"
    assert payload["logStream"] == "i-test12345"
    assert len(payload["logEvents"]) == 5
    assert "test_user" in payload["logEvents"][0]["message"]
    assert "198.51.100.99" in payload["logEvents"][0]["message"]


def test_simulate_threat_and_verify_success() -> None:
    """Lambda 호출 및 자동 롤백 복구 연계 성공 검증.

    Why:
        모의 주입 시 Lambda 응답 파싱과 자동 롤백 함수 호출이
        정상 트랜잭션으로 연계 완료되는지 목 클라이언트로 검증함.
    """
    mock_lambda = MagicMock()
    mock_ec2 = MagicMock()

    # Lambda 반환값 설정
    mock_response_payload = {
        "processed_events": 5,
        "threats_detected": ["SSH_BRUTE_FORCE"],
        "remediation_results": [{"quarantine_applied": True, "waf_blocked": True}],
        "slack_notified": True,
    }
    payload_bytes = json.dumps(mock_response_payload).encode("utf-8")

    mock_lambda.invoke.return_value = {
        "StatusCode": 200,
        "Payload": io.BytesIO(payload_bytes),
    }

    # EC2 describe_instances 반환값 설정
    mock_ec2.describe_instances.side_effect = [
        # 1차: 격리 SG 상태
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-test12345",
                            "SecurityGroups": [{"GroupId": "sg-quarantine"}],
                        }
                    ]
                }
            ]
        },
        # 2차: Baseline SG 복구 확인
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-test12345",
                            "SecurityGroups": [{"GroupId": "sg-baseline"}],
                        }
                    ]
                }
            ]
        },
    ]

    result = simulate_threat_and_verify(
        function_name="CloudShield-Threat-Orchestrator",
        instance_id="i-test12345",
        baseline_sg_id="sg-baseline",
        source_ip="198.51.100.50",
        auto_restore=True,
        lambda_client=mock_lambda,
        ec2_client=mock_ec2,
    )

    assert result["status"] == "success"
    assert result["status_code"] == 200
    assert result["threats_detected"] == ["SSH_BRUTE_FORCE"]
    assert result["slack_notified"] is True
    assert result["restore_result"]["status"] == "success"

    # mock 호출 검증
    mock_lambda.invoke.assert_called_once()
    mock_ec2.modify_instance_attribute.assert_called_once_with(
        InstanceId="i-test12345", Groups=["sg-baseline"]
    )


def test_simulate_threat_and_verify_function_error() -> None:
    """Lambda FunctionError 발생 시 status=failed 판정 검증.

    Why:
        HTTP 상태 코드가 200이더라도 Lambda 런타임 FunctionError가 반환되면
        대응 실패로 판정하여 오탐을 차단해야 함.
    """
    mock_lambda = MagicMock()
    mock_ec2 = MagicMock()

    mock_lambda.invoke.return_value = {
        "StatusCode": 200,
        "FunctionError": "Unhandled",
        "Payload": io.BytesIO(b'{"errorMessage": "Memory limit exceeded"}'),
    }

    result = simulate_threat_and_verify(
        function_name="CloudShield-Threat-Orchestrator",
        instance_id="i-test12345",
        auto_restore=False,
        lambda_client=mock_lambda,
        ec2_client=mock_ec2,
    )

    assert result["status"] == "failed"
    assert result["function_error"] == "Unhandled"


def test_simulate_threat_and_verify_slack_notified_false() -> None:
    """Slack 알림 전파 실패 시 status=failed 판정 검증."""
    mock_lambda = MagicMock()
    mock_ec2 = MagicMock()

    mock_response = {
        "threats_detected": ["SSH_BRUTE_FORCE"],
        "remediation_results": [{"quarantine_applied": True}],
        "slack_notified": False,
    }
    mock_lambda.invoke.return_value = {
        "StatusCode": 200,
        "Payload": io.BytesIO(json.dumps(mock_response).encode("utf-8")),
    }

    result = simulate_threat_and_verify(
        function_name="CloudShield-Threat-Orchestrator",
        instance_id="i-test12345",
        auto_restore=False,
        lambda_client=mock_lambda,
        ec2_client=mock_ec2,
    )

    assert result["status"] == "failed"
    assert result["slack_notified"] is False


def test_simulate_threat_and_verify_remediation_failure() -> None:
    """차단 조치 미집행 시 status=failed 판정 검증."""
    mock_lambda = MagicMock()
    mock_ec2 = MagicMock()

    mock_response = {
        "threats_detected": ["SSH_BRUTE_FORCE"],
        "remediation_results": [{"quarantine_applied": False, "status": "failed"}],
        "slack_notified": True,
    }
    mock_lambda.invoke.return_value = {
        "StatusCode": 200,
        "Payload": io.BytesIO(json.dumps(mock_response).encode("utf-8")),
    }

    result = simulate_threat_and_verify(
        function_name="CloudShield-Threat-Orchestrator",
        instance_id="i-test12345",
        auto_restore=False,
        lambda_client=mock_lambda,
        ec2_client=mock_ec2,
    )

    assert result["status"] == "failed"


def test_simulate_threat_and_verify_threats_detected_empty() -> None:
    """위협 미탐지 시 status=failed 판정 검증."""
    mock_lambda = MagicMock()
    mock_ec2 = MagicMock()

    mock_response = {
        "threats_detected": [],
        "remediation_results": [],
        "slack_notified": True,
    }
    mock_lambda.invoke.return_value = {
        "StatusCode": 200,
        "Payload": io.BytesIO(json.dumps(mock_response).encode("utf-8")),
    }

    result = simulate_threat_and_verify(
        function_name="CloudShield-Threat-Orchestrator",
        instance_id="i-test12345",
        auto_restore=False,
        lambda_client=mock_lambda,
        ec2_client=mock_ec2,
    )

    assert result["status"] == "failed"


def test_simulate_threat_and_verify_auto_restore_on_lambda_exception() -> None:
    """Lambda 호출 중 예외가 발생해도 Baseline SG 롤백이 반드시 수행되는지 검증.

    Why:
        Lambda 실행 단계에서 타임아웃이나 역직렬화 실패가 발생해도
        인프라가 격리 상태로 방치되지 않고 안전하게 원상 복구되어야 함.
    """
    mock_lambda = MagicMock()
    mock_ec2 = MagicMock()

    mock_lambda.invoke.side_effect = RuntimeError("Lambda network failure")

    mock_ec2.describe_instances.side_effect = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-test", "SecurityGroups": [{"GroupId": "sg-quarantine"}]}
                    ]
                }
            ]
        },
        {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-test", "SecurityGroups": [{"GroupId": "sg-baseline"}]}
                    ]
                }
            ]
        },
    ]

    with pytest.raises(RuntimeError, match="Lambda network failure"):
        simulate_threat_and_verify(
            function_name="CloudShield-Threat-Orchestrator",
            instance_id="i-test",
            baseline_sg_id="sg-baseline",
            auto_restore=True,
            lambda_client=mock_lambda,
            ec2_client=mock_ec2,
        )

    # 롤백 API가 반드시 호출되었는지 검증
    mock_ec2.modify_instance_attribute.assert_called_once_with(
        InstanceId="i-test", Groups=["sg-baseline"]
    )


def test_simulate_threat_and_verify_exception_chaining() -> None:
    """Lambda와 복구 모두 실패 시 원본 예외와 복구 예외가 체이닝되어 전파되는지 검증."""
    mock_lambda = MagicMock()
    mock_ec2 = MagicMock()

    mock_lambda.invoke.side_effect = ValueError("Original Lambda failure")
    mock_ec2.describe_instances.side_effect = RuntimeError("EC2 restore failure")

    with pytest.raises(RuntimeError, match="EC2 restore failure") as exc_info:
        simulate_threat_and_verify(
            function_name="CloudShield-Threat-Orchestrator",
            instance_id="i-test",
            baseline_sg_id="sg-baseline",
            auto_restore=True,
            lambda_client=mock_lambda,
            ec2_client=mock_ec2,
        )

    assert exc_info.value.__cause__ is not None
    assert isinstance(exc_info.value.__cause__, ValueError)
    assert "Original Lambda failure" in str(exc_info.value.__cause__)


def test_parse_args_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI 파서 기본값 설정 검증."""
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.delenv("LAMBDA_FUNCTION_NAME", raising=False)
    monkeypatch.delenv("TARGET_INSTANCE_ID", raising=False)
    monkeypatch.delenv("BASELINE_SG_ID", raising=False)

    args = parse_args([])
    assert args.function_name == DEFAULT_FUNCTION_NAME
    assert args.instance_id == DEFAULT_INSTANCE_ID
    assert args.baseline_sg_id == DEFAULT_BASELINE_SG_ID
    assert args.source_ip == DEFAULT_TEST_SOURCE_IP
    assert args.no_restore is False
