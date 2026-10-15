# CloudShield 단위 테스트: Baseline SG 롤백 복구 스크립트
# 소유자: 클라우드 A 담당
"""scripts/restore_baseline_sg.py 단위 테스트."""

from __future__ import annotations

from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from scripts.restore_baseline_sg import (
    parse_args,
    restore_baseline_security_group,
)

from conftest import MockEc2Target


def test_restore_baseline_security_group_success(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """격리 SG가 적용된 인스턴스를 Baseline SG로 정상 복구하는지 검증.

    Why:
        L4 차단 실측 후 타깃 EC2를 정상 운영 보안 그룹으로 복원하고
        T_restored 타임스탬프와 복구 소요 시간을 올바르게 기록하는지 검증함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    # 1. 인스턴스를 격리 SG 상태로 사전 변경
    ec2_client.modify_instance_attribute(
        InstanceId=mocked_ec2_target.instance_id,
        Groups=[mocked_ec2_target.quarantine_sg_id],
    )

    # 2. 롤백 복구 함수 호출
    result = restore_baseline_security_group(
        instance_id=mocked_ec2_target.instance_id,
        baseline_sg_id=mocked_ec2_target.normal_sg_id,
        ec2_client=ec2_client,
    )

    # 3. 결과 상태 및 실제 SG 상태 검증
    assert result["status"] == "success"
    assert result["instance_id"] == mocked_ec2_target.instance_id
    assert result["previous_security_groups"] == [mocked_ec2_target.quarantine_sg_id]
    assert result["current_security_groups"] == [mocked_ec2_target.normal_sg_id]
    assert "t_restored_iso" in result
    assert "t_restored_epoch" in result
    assert result["duration_ms"] >= 0

    # 4. EC2 재조회 검증
    desc = ec2_client.describe_instances(InstanceIds=[mocked_ec2_target.instance_id])
    sgs = [sg["GroupId"] for sg in desc["Reservations"][0]["Instances"][0]["SecurityGroups"]]
    assert sgs == [mocked_ec2_target.normal_sg_id]


def test_restore_baseline_security_group_idempotent(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """이미 Baseline SG가 적용된 경우 중복 API 호출 없이 멱등 처리하는지 검증.

    Why:
        반복 실행 또는 중복 호출 시 불필요한 인프라 변경 없이
        안전하게 status="unchanged"를 반환하여 멱등성을 보장함.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    # 이미 normal_sg_id 상태
    result = restore_baseline_security_group(
        instance_id=mocked_ec2_target.instance_id,
        baseline_sg_id=mocked_ec2_target.normal_sg_id,
        ec2_client=ec2_client,
    )

    assert result["status"] == "unchanged"
    assert result["previous_security_groups"] == [mocked_ec2_target.normal_sg_id]
    assert result["current_security_groups"] == [mocked_ec2_target.normal_sg_id]


def test_restore_baseline_security_group_instance_not_found(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """존재하지 않는 인스턴스 ID에 대해 적절한 예외가 발생하는지 검증."""
    ec2_client = boto3.client("ec2", region_name="us-east-1")

    with pytest.raises(ClientError):
        restore_baseline_security_group(
            instance_id="i-nonexistent999",
            baseline_sg_id=mocked_ec2_target.normal_sg_id,
            ec2_client=ec2_client,
        )


def test_restore_baseline_security_group_extra_sg_fails(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """복구 후 다른 보안 그룹이 함께 잔존하여 단독 적용 계약을 위반할 때 예외 검증."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.side_effect = [
        # 1차: 현재 격리 SG 상태
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": mocked_ec2_target.instance_id,
                            "SecurityGroups": [{"GroupId": mocked_ec2_target.quarantine_sg_id}],
                        }
                    ]
                }
            ]
        },
        # 2차 검증: Baseline SG 외에 다른 SG가 함께 잔존
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": mocked_ec2_target.instance_id,
                            "SecurityGroups": [
                                {"GroupId": mocked_ec2_target.normal_sg_id},
                                {"GroupId": "sg-extra-leaked"},
                            ],
                        }
                    ]
                }
            ]
        },
    ]

    with pytest.raises(RuntimeError, match="Baseline SG 단독 적용 불일치"):
        restore_baseline_security_group(
            instance_id=mocked_ec2_target.instance_id,
            baseline_sg_id=mocked_ec2_target.normal_sg_id,
            ec2_client=mock_ec2,
        )


def test_restore_baseline_security_group_mismatch_fails(
    mocked_ec2_target: MockEc2Target,
) -> None:
    """복구 후 완전히 다른 보안 그룹으로 조회될 때 예외 검증."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_instances.side_effect = [
        # 1차: 현재 격리 SG 상태
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": mocked_ec2_target.instance_id,
                            "SecurityGroups": [{"GroupId": mocked_ec2_target.quarantine_sg_id}],
                        }
                    ]
                }
            ]
        },
        # 2차 검증: 다른 SG만 존재
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": mocked_ec2_target.instance_id,
                            "SecurityGroups": [{"GroupId": "sg-wrong-group"}],
                        }
                    ]
                }
            ]
        },
    ]

    with pytest.raises(RuntimeError, match="Baseline SG 단독 적용 불일치"):
        restore_baseline_security_group(
            instance_id=mocked_ec2_target.instance_id,
            baseline_sg_id=mocked_ec2_target.normal_sg_id,
            ec2_client=mock_ec2,
        )


def test_parse_args_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI 파서 기본값 설정 검증."""
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    args = parse_args([])
    assert args.instance_id == "i-027b9d94be16b0d77"
    assert args.baseline_sg_id == "sg-07d8f7ea689ecd95e"
    assert args.region == "ap-southeast-2"
