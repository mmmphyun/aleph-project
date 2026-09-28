# CloudShield 수집 파이프라인: CloudWatch Logs 프로세서
# 소유자: 클라우드 B 담당
"""CloudWatch Logs Subscription Filter 수신 페이로드 디코딩, 라우팅 및 전처리 모듈.

Why:
    CloudWatch Logs 구독 필터가 Lambda 함수를 호출할 때 전달하는
    Base64 인코딩 및 Gzip 압축된 이진 페이로드를 안전하게 해제하여
    SSH 인증 로그와 Nginx 접근 로그를 스트림별로 분기 라우팅하고,
    At-least-once 전송 환경에서 이벤트 중복 처리를 방지하여 멱등성을 보장함.

Constraints:
    - 입력 payload 딕셔너리는 {"awslogs": {"data": "<base64_gzip_str>"}} 구조를 만족해야 함.
    - 표준 라이브러리 base64, gzip, json 또는 contracts.events.CloudWatchLogsPayload 활용.
    - CloudShield 단일 10초 관통 대응 SLA 준수를 위해 수집 지연 3초 이내 전처리 보장.
"""

from __future__ import annotations

from typing import Any

from contracts.events import CloudWatchLogEvent, CloudWatchLogsPayload

# SSH 인증 실패 전용 구독 필터 파라미터 명세 (하위 호환성 유지)
SUBSCRIPTION_FILTER_SPEC: dict[str, Any] = {
    "filter_name": "CloudShield-SSH-FailedPassword-Filter",
    "log_group_name": "/cloudshield/target/auth-log",
    "filter_pattern": '"Failed password"',
    "destination_type": "lambda",
    "destination_arn": "${aws_lambda_function.threat_orchestrator.arn}",
}

# Nginx L7 웹 접근 로그 전용 구독 필터 파라미터 명세 (시나리오 2 Web L7 대응)
NGINX_SUBSCRIPTION_FILTER_SPEC: dict[str, Any] = {
    "filter_name": "CloudShield-Nginx-Access-Filter",
    "log_group_name": "/cloudshield/target/nginx-access-log",
    "filter_pattern": "{ ($.status = 401) || ($.status = 403) || ($.status = 404) }",
    "destination_type": "lambda",
    "destination_arn": "${aws_lambda_function.threat_orchestrator.arn}",
}

# 다중 스트림 구독 필터 통합 딕셔너리
SUBSCRIPTION_FILTER_SPECS: dict[str, dict[str, Any]] = {
    "auth": SUBSCRIPTION_FILTER_SPEC,
    "nginx": NGINX_SUBSCRIPTION_FILTER_SPEC,
}

# 로그 그룹 경로와 스트림 유형 매핑 매트릭스
LOG_GROUP_STREAM_MAPPING: dict[str, str] = {
    "/cloudshield/target/auth-log": "auth",
    "/cloudshield/target/nginx-access-log": "nginx",
}


def matches_subscription_filter(
    log_line: str,
    pattern: str | None = None,
) -> bool:
    """CloudWatch Logs 구독 필터 패턴 매칭 검사.

    Why:
        클라우드 B 수집 파이프라인에서 실제 AWS CloudWatch Logs 구독 필터가
        대량의 정상 로그 중 의심 키워드('Failed password')가 포함된 라인만 선별하여
        Lambda로 포워딩하는 동작을 로컬 테스트베드에서 완벽히 시뮬레이션하기 위함.
        CloudWatch Logs 비정형 텍스트 필터("...") 및 공백 구분 필터([...])를 모의 평가함.

    Constraints:
        - log_line: 원시 Syslog 한 줄 문자열.
        - pattern: CloudWatch Logs 필터 패턴 (기본값: SUBSCRIPTION_FILTER_SPEC["filter_pattern"]).

    Side-effects / Edge-cases:
        - log_line이 비어 있거나 문자열이 아닌 경우 False 반환.
        - 따옴표 구문("Failed password"): 전체 로그에서 대소문자 구분 exact phrase 매칭.
        - 공백 구분 패턴([...]): 공백 토큰 인덱스별 조건식 평가 (단일 토큰 불일치 시 False).
    """
    if not log_line or not isinstance(log_line, str):
        return False

    default_pattern = SUBSCRIPTION_FILTER_SPEC.get("filter_pattern", '"Failed password"')
    active_pattern = pattern if pattern is not None else default_pattern
    active_pattern = active_pattern.strip()

    # 1. 비정형 구문 매칭: "..." (Exact phrase match)
    # Why: BSD(Sep 03...) 및 ISO 8601 타임스탬프 형식 차이에 구애받지 않고
    #      로그 라인 전체에서 'Failed password' 정확한 구문을 탐색함.
    if active_pattern.startswith('"') and active_pattern.endswith('"') and len(active_pattern) >= 2:
        phrase = active_pattern[1:-1]
        return phrase in log_line

    # 2. 공백 구분 필드 매칭: [...] (Space-delimited filter)
    # Why: CloudWatch Logs의 공백 분리 필터 구문을 모의하여 단일 토큰 비교 동작을 시뮬레이션함.
    if active_pattern.startswith("[") and active_pattern.endswith("]"):
        field_specs = [f.strip() for f in active_pattern[1:-1].split(",") if f.strip()]
        tokens = log_line.split()

        for idx, field_spec in enumerate(field_specs):
            if field_spec == "...":
                break
            if "=" in field_spec:
                _field_name, expected_val = [x.strip() for x in field_spec.split("=", 1)]
                expected_val = expected_val.strip("\"'")
                if idx >= len(tokens):
                    return False
                token_val = tokens[idx]
                if expected_val.startswith("*") and expected_val.endswith("*"):
                    clean_val = expected_val[1:-1]
                    if clean_val not in token_val:
                        return False
                elif expected_val != token_val:
                    return False

        return True

    # 3. 일반 키워드 검색 (Fallback)
    return active_pattern in log_line


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


def deduplicate_log_events(
    events: list[CloudWatchLogEvent],
    seen_event_ids: set[str],
) -> list[CloudWatchLogEvent]:
    """CloudWatch 로그 이벤트 목록에서 중복 ID를 필터링하여 At-least-once 전달 대비 멱등성 보장.

    Why:
        AWS CloudWatch Logs Subscription Filter는 최소 1회(At-least-once) 전달을 보장하므로
        네트워크 일시 단절 또는 Lambda 타임아웃 재시도 시 동일한 로그 이벤트가 재인입될 수 있음.
        이벤트 ID를 기준으로 이미 처리된 레코드를 선제 제거하여 보안 윈도우의
        비정상 과다 누적을 방지함.

    Constraints:
        - events: CloudWatchLogEvent 인스턴스 리스트.
        - seen_event_ids: 이미 처리되었거나 관측된 이벤트 ID 세트 (신규 ID 추가됨).

    Side-effects / Edge-cases:
        - seen_event_ids 세트가 직접 변경(in-place update)됨.
    """
    unique_events: list[CloudWatchLogEvent] = []
    for event in events:
        if event.id in seen_event_ids:
            continue
        seen_event_ids.add(event.id)
        unique_events.append(event)
    return unique_events


def route_cw_logs(
    payload: dict[str, Any],
    seen_event_ids: set[str] | None = None,
) -> dict[str, Any]:
    """CloudWatch Logs 이벤트를 디코딩하고 logGroup에 따라 적절한 스트림 유형으로 라우팅.

    Why:
        SSH 인증 실패 로그(/var/log/auth.log)와 Nginx L7 웹 접근 로그(/var/log/nginx/access.log)가
        동일한 Lambda 오케스트레이터로 인입될 때, logGroup 경로를 기준으로 스트림 유형을 식별하고
        후속 분석 엔진(SyslogAuthEvent 파서 vs Nginx 파서/WAF 탐지 룰)으로 안전하게 분기함.
        또한, AWS CloudWatch Logs -> Lambda 구독 필터의 At-least-once 재전송 메커니즘으로 인한
        중복 이벤트 인입을 차단하여 멱등성(Idempotency)을 보장함.

    Constraints:
        - payload: {"awslogs": {"data": "<base64_gzip_str>"}} 구조의 딕셔너리.
        - seen_event_ids: 이미 처리된 CloudWatch 로그 이벤트 ID 집합 (선택적).
        - 반환 dict 구조:
          {
              "stream_type": "auth" | "nginx" | "unknown",
              "log_group": str,
              "log_stream": str,
              "messages": list[str],
              "event_ids": list[str],
              "subscription_filters": list[str],
              "dropped_duplicates": int,
          }

    Side-effects / Edge-cases:
        - payload가 dict가 아니거나 필수 키 누락 시 decode_cw_logs와 동일하게
          TypeError/KeyError/ValueError 발생.
        - logGroup이 등록된 스트림 경로와 불일치할 경우 stream_type은 "unknown"으로
          안전하게 격리 분류.
        - seen_event_ids 세트가 제공된 경우 이미 존재하는 event_id는 필터링되고
          세트에 신규 event_id 추가.
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

    try:
        cw_payload = CloudWatchLogsPayload.from_awslogs_data(raw_data)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"CloudWatch Logs 페이로드 해제 실패: {exc}") from exc

    log_group = cw_payload.logGroup
    stream_type = LOG_GROUP_STREAM_MAPPING.get(log_group, "unknown")

    raw_events = cw_payload.logEvents
    total_raw_count = len(raw_events)

    if seen_event_ids is not None:
        filtered_events = deduplicate_log_events(raw_events, seen_event_ids)
        dropped_count = total_raw_count - len(filtered_events)
    else:
        filtered_events = raw_events
        dropped_count = 0

    messages = [event.message for event in filtered_events]
    event_ids = [event.id for event in filtered_events]

    return {
        "stream_type": stream_type,
        "log_group": log_group,
        "log_stream": cw_payload.logStream,
        "messages": messages,
        "event_ids": event_ids,
        "subscription_filters": list(cw_payload.subscriptionFilters),
        "dropped_duplicates": dropped_count,
    }
