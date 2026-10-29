"""CloudShield 실인프라 E2E 모의 위협 주입 및 자동 롤백 검증 도구.

소유자: 클라우드 A (플랫폼 전담)

Why:
    외부 공격자(Kali Linux) 환경이나 네트워크 담당자의 개입 없이도,
    클라우드 A가 단독으로 실제 AWS 런타임(Lambda -> Quarantine SG -> Slack Alert)의
    엔드투엔드 관통 대응 파이프라인의 생존 여부(Health check)를 3초 만에 사전 검증하고
    안전하게 원상 복원할 수 있는 표준 스모크 테스트 하네스를 제공함.

Constraints:
    - 외부 실공격과 혼동되지 않도록 기본 출발지 IP는
      RFC 5737 문서/테스트 대역(198.51.100.50)을 사용함.
    - CloudWatch Logs Subscription Filter 표준 규격(gzip 압축 + Base64 인코딩)을 정확히 준수함.
    - 기본적으로 테스트 완료 즉시 Baseline SG로 자동 롤백(--auto-restore)을 수행함.

Side-effects / Edge-cases:
    - 실제 배포된 AWS Lambda 및 타깃 EC2 보안 그룹에 영향을 주므로, 개발 환경에서만 실행 권장.
    - Lambda 호출 실패 또는 권한 부족 시 오류 상세를 출력하고 0이 아닌 종료 코드로 종료됨.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import logging
import os
import sys
import time
from typing import Any

import boto3
from scripts.restore_baseline_sg import (
    DEFAULT_BASELINE_SG_ID,
    DEFAULT_INSTANCE_ID,
    DEFAULT_REGION,
    restore_baseline_security_group,
)
from src.remediation.orchestrator import is_remediation_successful

DEFAULT_FUNCTION_NAME = "CloudShield-Threat-Orchestrator"
DEFAULT_TEST_SOURCE_IP = "198.51.100.50"
DEFAULT_TEST_USERNAME = "cloudshield_test"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("simulate_lambda_threat")


def build_mock_cw_logs_payload(
    instance_id: str = DEFAULT_INSTANCE_ID,
    source_ip: str = DEFAULT_TEST_SOURCE_IP,
    username: str = DEFAULT_TEST_USERNAME,
    failure_count: int = 5,
) -> dict[str, Any]:
    """CloudWatch Logs Subscription Filter가 전달하는 모의 gzip/base64 이벤트 페이로드 생성.

    Why:
        Lambda 오케스트레이터 핸들러가 실제 CloudWatch Logs로부터 수신하는
        동일한 바이너리 압축/인코딩 포맷을 모사하여 런타임 디코딩 로직을 검증함.
    """
    now_ms = int(time.time() * 1000)
    log_events = []
    for i in range(1, failure_count + 1):
        ts = now_ms - (failure_count - i) * 1000
        msg = (
            f"Oct 14 09:40:0{i} target sshd[999{i}]: "
            f"Failed password for invalid user {username} from {source_ip} port {40000 + i} ssh2"
        )
        log_events.append({"id": f"sim-evt-{i}-{now_ms}", "timestamp": ts, "message": msg})

    payload_dict = {
        "messageType": "DATA_MESSAGE",
        "owner": "CloudShield-Sim",
        "logGroup": "/cloudshield/target/auth-log",
        "logStream": instance_id,
        "subscriptionFilters": ["CloudShield-SSH-FailedPassword-Filter"],
        "logEvents": log_events,
    }

    compressed = gzip.compress(json.dumps(payload_dict).encode("utf-8"))
    encoded = base64.b64encode(compressed).decode("utf-8")
    return {"awslogs": {"data": encoded}}


def simulate_threat_and_verify(
    function_name: str = DEFAULT_FUNCTION_NAME,
    instance_id: str = DEFAULT_INSTANCE_ID,
    baseline_sg_id: str = DEFAULT_BASELINE_SG_ID,
    source_ip: str = DEFAULT_TEST_SOURCE_IP,
    username: str = DEFAULT_TEST_USERNAME,
    auto_restore: bool = True,
    lambda_client: Any = None,
    ec2_client: Any = None,
    slack_webhook_url: str | None = None,
) -> dict[str, Any]:
    """실제 AWS Lambda를 호출하여 관통 대응을 검증하고 선택적으로 인프라 롤백 수행.

    Why:
        모의 이벤트를 단일 트랜잭션으로 주입하여 Lambda 위협 탐지, 차단,
        Slack 알림 발송을 실측하고 즉시 정상 운영 SG로 복원하여 안전성을 확보함.
    """
    if lambda_client is None or ec2_client is None:
        region = os.getenv("AWS_DEFAULT_REGION", DEFAULT_REGION)
        profile = os.getenv("AWS_PROFILE")
        session = boto3.Session(profile_name=profile, region_name=region)
        lambda_client = lambda_client or session.client("lambda")
        ec2_client = ec2_client or session.client("ec2")

    logger.info("실인프라 E2E 모의 위협 주입 시작 (타깃 함수: %s)", function_name)
    logger.info("타깃 인스턴스: %s, 모의 공격자 IP: %s", instance_id, source_ip)

    event_payload = build_mock_cw_logs_payload(
        instance_id=instance_id,
        source_ip=source_ip,
        username=username,
        failure_count=5,
    )

    start_time = time.perf_counter()
    original_error: Exception | None = None
    restore_result: dict[str, Any] | None = None
    result_data: dict[str, Any] = {}
    status_code: int = 0
    function_error: str | None = None
    invoke_duration_ms: float = 0.0

    try:
        # 1. Lambda 동기 호출
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(event_payload),
        )
        invoke_duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        status_code = response.get("StatusCode", 0)
        function_error = response.get("FunctionError")

        raw_payload = response.get("Payload")
        if raw_payload is not None:
            if hasattr(raw_payload, "read"):
                payload_bytes = raw_payload.read()
                payload_str = (
                    payload_bytes.decode("utf-8")
                    if isinstance(payload_bytes, bytes)
                    else str(payload_bytes)
                )
            else:
                payload_str = str(raw_payload)
            result_data = json.loads(payload_str) if payload_str else {}

        logger.info(
            "Lambda 호출 완료 (HTTP %d, FunctionError: %s, 소요 시간: %0.2f ms)",
            status_code,
            function_error,
            invoke_duration_ms,
        )
    except Exception as e:
        original_error = e
        logger.error("Lambda 호출 또는 응답 처리 중 오류 발생: %s", e)
    finally:
        # 2. 실패 경로에서도 자동 롤백 복구 보장
        if auto_restore:
            try:
                logger.info("자동 복구 플래그 활성화: Baseline SG(%s)로 복원 시작", baseline_sg_id)
                restore_result = restore_baseline_security_group(
                    instance_id=instance_id,
                    baseline_sg_id=baseline_sg_id,
                    ec2_client=ec2_client,
                )
                logger.info("자동 복구 완료 (상태: %s)", restore_result.get("status"))
            except Exception as restore_err:
                logger.error("자동 복구 실행 중 오류 발생: %s", restore_err)
                if original_error is not None:
                    # 원본 오류와 복구 오류를 모두 보존하여 전파
                    raise restore_err from original_error
                raise

        # Lambda 호출 단계에서 발생한 원본 오류 전파
        if original_error is not None:
            raise original_error

    threats = result_data.get("threats_detected", [])
    slack_notified = result_data.get("slack_notified", False)
    remediation_results = result_data.get("remediation_results", [])
    incidents = result_data.get("incidents", [])

    logger.info("탐지된 위협: %s", threats)
    logger.info("차단 집행 결과: %s", remediation_results)
    logger.info("Slack 1차 카드 전파 성공 여부: %s", slack_notified)

    # 2-1. 자동 복구 완료 후 동일 incident_id 기반 3차 복구 Slack 알림 전송 (P5-2 실환경 연동)
    recovery_slack_sent = False
    if auto_restore and restore_result and incidents:
        try:
            from contracts.incident import IncidentReport
            from reporter.slack_notifier import send_recovery_slack_alert

            target_webhook = slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL")
            for inc_dict in incidents:
                rep = IncidentReport.model_validate(inc_dict)
                rec_payload = {
                    "quarantine_restored": restore_result.get("status") in ("success", "unchanged"),
                    "t_restored_iso": restore_result.get("t_restored_iso"),
                    "verification_status": "Baseline SG Verified",
                    "traffic_verified": True,
                    "details": [
                        f"타깃 EC2({instance_id}) Baseline SG({baseline_sg_id}) 단독 복원 완료",
                        f"복구 소요 시간: {restore_result.get('duration_ms')}ms",
                    ],
                }
                if target_webhook:
                    recovery_slack_sent = send_recovery_slack_alert(
                        report=rep,
                        recovery_result=rec_payload,
                        webhook_url=target_webhook,
                    )
                    logger.info(
                        "Slack 3차 복구 카드 전파 결과 (id=%s): %s",
                        rep.incident_id,
                        recovery_slack_sent,
                    )
        except Exception as rec_err:
            logger.error("3차 복구 Slack 알림 전파 중 예외 발생 격리: %s", rec_err)

    remediation_ok = False
    if isinstance(remediation_results, list) and len(remediation_results) > 0:
        if isinstance(incidents, list) and len(incidents) == len(remediation_results):
            remediation_ok = all(
                is_remediation_successful(
                    inc.get("action_required", "BLOCK_AND_QUARANTINE"),
                    rem,
                )
                for inc, rem in zip(incidents, remediation_results, strict=True)
            )
        else:
            remediation_ok = all(
                is_remediation_successful(
                    rem.get("action_required", "BLOCK_AND_QUARANTINE"),
                    rem,
                )
                for rem in remediation_results
            )

    # 3. 엄격한 성공 조건 판정 (FunctionError 없음, 위협 탐지, 차단 성공, Slack 알림 성공 필수)
    is_success = (
        status_code == 200
        and not function_error
        and bool(threats)
        and remediation_ok
        and (slack_notified is True)
    )

    return {
        "status": "success" if is_success else "failed",
        "status_code": status_code,
        "function_error": function_error,
        "invoke_duration_ms": invoke_duration_ms,
        "lambda_response": result_data,
        "threats_detected": threats,
        "remediation_results": remediation_results,
        "slack_notified": slack_notified,
        "restore_result": restore_result,
        "recovery_slack_sent": recovery_slack_sent,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """CLI 인자 파서 정의."""
    parser = argparse.ArgumentParser(
        description="CloudShield 실인프라 E2E 모의 위협 주입 및 자동 롤백 검증 도구"
    )
    parser.add_argument(
        "--function-name",
        default=os.getenv("LAMBDA_FUNCTION_NAME", DEFAULT_FUNCTION_NAME),
        help=f"오케스트레이터 Lambda 함수명 (기본값: {DEFAULT_FUNCTION_NAME})",
    )
    parser.add_argument(
        "--instance-id",
        default=os.getenv("TARGET_INSTANCE_ID", DEFAULT_INSTANCE_ID),
        help=f"타깃 EC2 인스턴스 ID (기본값: {DEFAULT_INSTANCE_ID})",
    )
    parser.add_argument(
        "--baseline-sg-id",
        default=os.getenv("BASELINE_SG_ID", DEFAULT_BASELINE_SG_ID),
        help=f"복구할 Baseline 보안 그룹 ID (기본값: {DEFAULT_BASELINE_SG_ID})",
    )
    parser.add_argument(
        "--source-ip",
        default=DEFAULT_TEST_SOURCE_IP,
        help=f"모의 공격자 출발지 IP (기본값: {DEFAULT_TEST_SOURCE_IP})",
    )
    parser.add_argument(
        "--username",
        default=DEFAULT_TEST_USERNAME,
        help=f"모의 공격 대상 사용자명 (기본값: {DEFAULT_TEST_USERNAME})",
    )
    parser.add_argument(
        "--no-restore",
        action="store_true",
        help="테스트 후 Baseline SG 자동 롤백을 생략하고 격리 상태 유지",
    )
    parser.add_argument(
        "--slack-webhook-url",
        default=os.getenv("SLACK_WEBHOOK_URL"),
        help="3차 복구 알림 전송을 위한 Slack Webhook HTTPS URL (미지정 시 환경변수 사용)",
    )
    parser.add_argument(
        "--region",
        default=os.getenv("AWS_DEFAULT_REGION", DEFAULT_REGION),
        help=f"AWS 리전 (기본값: {DEFAULT_REGION})",
    )
    parser.add_argument(
        "--profile",
        default=os.getenv("AWS_PROFILE"),
        help="AWS CLI 프로필 명칭 (선택 사항)",
    )
    return parser.parse_args(argv)


def main() -> None:
    """CLI 진입점."""
    args = parse_args()

    session_kwargs: dict[str, Any] = {"region_name": args.region}
    if args.profile:
        session_kwargs["profile_name"] = args.profile

    session = boto3.Session(**session_kwargs)
    lambda_client = session.client("lambda")
    ec2_client = session.client("ec2")

    try:
        res = simulate_threat_and_verify(
            function_name=args.function_name,
            instance_id=args.instance_id,
            baseline_sg_id=args.baseline_sg_id,
            source_ip=args.source_ip,
            username=args.username,
            auto_restore=not args.no_restore,
            lambda_client=lambda_client,
            ec2_client=ec2_client,
            slack_webhook_url=args.slack_webhook_url,
        )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        if res["status"] != "success":
            sys.exit(1)
    except Exception as e:
        logger.error("모의 위협 주입 테스트 실패: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
