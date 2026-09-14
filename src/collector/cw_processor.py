# CloudShield 수집 파이프라인: CloudWatch Logs 프로세서
# 소유자: 클라우드 B 담당
"""CloudWatch Logs Subscription Filter 수신 페이로드 디코딩 및 전처리 모듈.

Why:
    CloudWatch Logs 구독 필터가 Lambda 함수를 호출할 때 전달하는
    Base64 인코딩 및 Gzip 압축된 이진 페이로드를 안전하게 해제하여
    개별 로그 메시지 라인 목록을 복원함.

Constraints:
    - 입력 payload 딕셔너리는 {"awslogs": {"data": "<base64_gzip_str>"}} 구조를 만족해야 함.
    - 표준 라이브러리 base64, gzip, json 또는 contracts.events.CloudWatchLogsPayload 활용.
"""

from __future__ import annotations

from typing import Any

from contracts.events import CloudWatchLogsPayload

# 클라우드 A Terraform IaC(aws_cloudwatch_log_subscription_filter) 연계용 구독 필터 파라미터 명세
SUBSCRIPTION_FILTER_SPEC: dict[str, Any] = {
    "filter_name": "CloudShield-SSH-FailedPassword-Filter",
    "log_group_name": "/cloudshield/target/auth-log",
    "filter_pattern": '[mon, day, timestamp, host, process, msg = "*Failed password*", ...]',
    "destination_type": "lambda",
    "destination_arn": "${aws_lambda_function.threat_orchestrator.arn}",
}


def matches_subscription_filter(
    log_line: str,
    keyword: str = "Failed password",
) -> bool:
    """CloudWatch Logs 구독 필터 패턴([..., msg = "*Failed password*", ...])의 로컬 모의 매칭 검사.

    Why:
        클라우드 B 수집 파이프라인에서 실제 AWS CloudWatch Logs 구독 필터가
        대량의 정상 로그 중 'Failed password' 키워드가 포함된 라인만 선별하여
        Lambda로 포워딩하는 동작을 로컬 테스트베드에서 완벽히 시뮬레이션하기 위함.

    Constraints:
        - log_line: 원시 Syslog 한 줄 문자열.
        - keyword: 필터링 대상 의심 키워드 (기본값: 'Failed password').
    """
    if not log_line or not isinstance(log_line, str):
        return False
    return keyword in log_line


def decode_cw_logs(payload: dict[str, Any]) -> list[str]:
    """CloudWatch Logs 이벤트 페이로드를 디코딩 및 압축 해제하여 로그 문자열 목록 반환.

    Why:
        압축 전송된 JSON 페이로드에서 logEvents 내부의 개별 message 문자열을 추출하여
        SyslogAuthEvent 파서 및 보안 룰 엔진(evaluate_rules)이 처리할 수 있는 리스트 형태로 가공함.
        (추출된 각 라인은 SyslogAuthEvent.parse_line()을 거쳐 모델 인스턴스로 변환됨)

    Constraints:
        - payload: AWS Lambda에 전달된 이벤트 딕셔너리 {"awslogs": {"data": "<base64_gzip_str>"}}.
        - 반환값: 각 로그 레코드의 message 문자열 리스트.

    Side-effects / Edge-cases:
        - payload 내 'awslogs' 키 또는 'data' 필드가 누락된 경우 KeyError 발생.
        - 손상되었거나 유효하지 않은 Base64/Gzip 데이터 인입 시 ValueError 발생.
        - logEvents가 비어 있는 경우 빈 리스트([])를 안전하게 반환함.
    """
    if not isinstance(payload, dict):
        raise TypeError(f"payload는 dict 타입이어야 합니다. (입력 타입: {type(payload).__name__})")

    if "awslogs" not in payload:
        raise KeyError("페이로드에 필수 키 'awslogs'가 누락되었습니다.")

    awslogs = payload["awslogs"]
    if not isinstance(awslogs, dict) or "data" not in awslogs:
        raise KeyError("페이로드의 'awslogs' 내에 필수 키 'data'가 누락되었습니다.")

    raw_data = awslogs["data"]
    if not isinstance(raw_data, str):
        raise ValueError("awslogs['data']는 Base64 인코딩된 문자열이어야 합니다.")

    # 1단계: Base64 디코딩 및 Gzip 압축 해제 (contracts.events.CloudWatchLogsPayload 활용)
    # Why: 공통 데이터 계약 모델을 준수하여 계층 간 스키마 일관성을 보장하고
    #      손상된 압축 스트림 및 JSON 역직렬화 오류를 안전하게 포착함.
    try:
        cw_payload = CloudWatchLogsPayload.from_awslogs_data(raw_data)
        return [event.message for event in cw_payload.logEvents]
    except ValueError:
        # Pydantic 모델 파싱 실패 시 상위로 전파
        raise
    except Exception as exc:
        raise ValueError(f"CloudWatch Logs 페이로드 해제 실패: {exc}") from exc
