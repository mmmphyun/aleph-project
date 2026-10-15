# CloudShield 단위 테스트: 시나리오 1 관통 실측 모니터링 도구
# 소유자: 클라우드 A 담당
"""scripts/measure_pipeline.py 단위 테스트."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from scripts.measure_pipeline import (
    DEFAULT_INSTANCE_ID,
    DEFAULT_QUARANTINE_SG_ID,
    monitor_quarantine,
    parse_args,
)


def test_monitor_quarantine_success_with_matching_log() -> None:
    """격리 SG 부착 및 사건 매칭 차단 로그가 정상 계측되는지 검증.

    Why:
        EC2 보안 그룹 전이와 인시던트 식별자가 포함된 Lambda 차단 완료 로그를
        정확히 매핑하여 T_sg_verified와 T_block을 동시 확정하는지 검증함.
    """
    mock_ec2 = MagicMock()
    mock_logs = MagicMock()

    # EC2 격리 SG 감지
    mock_ec2.describe_instances.return_value = {
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
    }

    # CloudWatch Logs에 사건 ID가 포함된 차단 완료 로그 반환
    mock_logs.filter_log_events.return_value = {
        "events": [
            {
                "timestamp": 1791953270994,
                "message": "[INC-1234] 198.51.100.50 L4 격리 완료 (Quarantine SG 교체 성공)",
            }
        ]
    }

    res = monitor_quarantine(
        instance_id="i-test12345",
        quarantine_sg_id="sg-quarantine",
        incident_id="INC-1234",
        source_ip="198.51.100.50",
        timeout_seconds=5,
        poll_interval=0.01,
        ec2_client=mock_ec2,
        logs_client=mock_logs,
    )

    assert res["status"] == "quarantined"
    assert res["t_sg_verified_iso"] is not None
    assert res["t_block_iso"] is not None
    assert res["t_block_epoch"] == 1791953270.994
    assert res["incident_id"] == "INC-1234"


def test_monitor_quarantine_unconfirmed_t_block_when_incident_mismatch() -> None:
    """사건 미일치 로그 발생 시 T_block을 임의 할당하지 않고 미확정(None)으로 유지하는지 검증.

    Why:
        사건과 무관한 타 람다 실행 로그나 마지막 이벤트를 T_block으로 오지정하는
        오탐 결함을 차단하고, 매칭 실패 시 None으로 명시적 유지해야 함.
    """
    mock_ec2 = MagicMock()
    mock_logs = MagicMock()

    mock_ec2.describe_instances.return_value = {
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
    }

    # 다른 인시던트(INC-9999)의 차단 로그만 존재하는 경우
    mock_logs.filter_log_events.return_value = {
        "events": [
            {
                "timestamp": 1791953299999,
                "message": "[INC-9999] 203.0.113.10 L4 격리 완료",
            }
        ]
    }

    res = monitor_quarantine(
        instance_id="i-test12345",
        quarantine_sg_id="sg-quarantine",
        incident_id="INC-1234",  # 매칭 대상
        source_ip="198.51.100.50",
        timeout_seconds=5,
        poll_interval=0.01,
        ec2_client=mock_ec2,
        logs_client=mock_logs,
    )

    assert res["status"] == "quarantined"
    assert res["t_sg_verified_iso"] is not None
    # 마지막 이벤트(INC-9999)를 T_block으로 지정하지 않고 None 유지 검증
    assert res["t_block_iso"] is None
    assert res["t_block_epoch"] is None


def test_monitor_quarantine_timeout() -> None:
    """지정 시간 내 격리 SG 미부착 시 status=timeout 반환 검증."""
    mock_ec2 = MagicMock()
    mock_logs = MagicMock()

    # 정상 SG 상태 유지 (격리 SG 미진입)
    mock_ec2.describe_instances.return_value = {
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
    }

    res = monitor_quarantine(
        instance_id="i-test12345",
        quarantine_sg_id="sg-quarantine",
        timeout_seconds=0,  # 즉시 타임아웃
        poll_interval=0.01,
        ec2_client=mock_ec2,
        logs_client=mock_logs,
    )

    assert res["status"] == "timeout"
    assert res["t_sg_verified_iso"] is None
    assert res["t_block_iso"] is None


def test_monitor_quarantine_no_identifier_leaves_t_block_none() -> None:
    """식별자(incident_id, source_ip) 미지정 시 T_block을 확정하지 않고 None 유지 검증."""
    mock_ec2 = MagicMock()
    mock_logs = MagicMock()

    mock_ec2.describe_instances.return_value = {
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
    }
    mock_logs.filter_log_events.return_value = {
        "events": [
            {
                "timestamp": 1791953270994,
                "message": "L4 격리 완료 (임의의 로그)",
            }
        ]
    }

    res = monitor_quarantine(
        instance_id="i-test12345",
        quarantine_sg_id="sg-quarantine",
        incident_id=None,
        source_ip=None,
        timeout_seconds=5,
        poll_interval=0.01,
        ec2_client=mock_ec2,
        logs_client=mock_logs,
    )

    assert res["status"] == "quarantined"
    assert res["t_block_iso"] is None
    assert res["t_block_epoch"] is None


def test_monitor_quarantine_failure_log_excluded() -> None:
    """차단 실패 로그 메시지가 존재하는 경우 T_block으로 오판하지 않고 None 유지 검증."""
    mock_ec2 = MagicMock()
    mock_logs = MagicMock()

    mock_ec2.describe_instances.return_value = {
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
    }
    mock_logs.filter_log_events.return_value = {
        "events": [
            {
                "timestamp": 1791953270994,
                "message": "[INC-1234] 198.51.100.50 L4 격리 실패 (ClientError)",
            }
        ]
    }

    res = monitor_quarantine(
        instance_id="i-test12345",
        quarantine_sg_id="sg-quarantine",
        incident_id="INC-1234",
        source_ip="198.51.100.50",
        timeout_seconds=5,
        poll_interval=0.01,
        ec2_client=mock_ec2,
        logs_client=mock_logs,
    )

    assert res["status"] == "quarantined"
    assert res["t_block_iso"] is None
    assert res["t_block_epoch"] is None


def test_main_cli_timeout_exits_code_1(monkeypatch: pytest.MonkeyPatch) -> None:
    """격리 감지 타임아웃 시 CLI가 종료 코드 1로 종료되는지 검증."""
    from scripts.measure_pipeline import main

    monkeypatch.setattr(
        "scripts.measure_pipeline.monitor_quarantine",
        lambda **kwargs: {"status": "timeout"},
    )
    monkeypatch.setattr("scripts.measure_pipeline.parse_args", lambda: MagicMock())

    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1


def test_main_cli_success_exits_0(monkeypatch: pytest.MonkeyPatch) -> None:
    """정상 격리 감지 시 CLI가 종료 코드 0으로 정상 완료되는지 검증."""
    from scripts.measure_pipeline import main

    monkeypatch.setattr(
        "scripts.measure_pipeline.monitor_quarantine",
        lambda **kwargs: {"status": "quarantined"},
    )
    monkeypatch.setattr("scripts.measure_pipeline.parse_args", lambda: MagicMock())

    # 정상 완료 시 SystemExit 미발생
    main()


def test_parse_args_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI 파서 기본값 설정 검증."""
    args = parse_args([])
    assert args.instance_id == DEFAULT_INSTANCE_ID
    assert args.quarantine_sg_id == DEFAULT_QUARANTINE_SG_ID
    assert args.incident_id is None
    assert args.source_ip is None
    assert args.timeout == 300
    assert args.interval == 0.5
