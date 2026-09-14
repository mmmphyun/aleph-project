# CloudWatch Logs 구독 필터(Subscription Filter) 및 모의 Lambda 연계 명세서

- **작성일**: 2026-09-14
- **작성자**: 클라우드 B 담당자
- **관련 파일**: `src/collector/cw_processor.py`, `src/collector/amazon-cloudwatch-agent.json`, `tests/unit/test_collector.py`
- **산출물 목표**: CloudWatch Logs에 수집되는 타깃 인증 로그 중 의심 키워드(`Failed password`)가 포함된 라인만 선별하여 클라우드 A가 배포한 분석용 Lambda 오케스트레이터로 전달하는 구독 규칙(Subscription Filter) 설정 파라미터 도출 및 Terraform 모듈 연계 인터페이스 제공.

---

## 1. 개요 및 10초 관통 아키텍처 상의 역할

CloudShield의 단일 10초 관통 대응 파이프라인(`공격 발생 -> 중앙 수집 -> 분석/오케스트레이션 -> 다중 차단 -> Slack 전파`)에서 **구독 필터(Subscription Filter)**는 대용량 실시간 로그 스트림과 서버리스 분석 엔진을 잇는 핵심 필터링 게이트웨이 역할을 수행합니다.

```text
[타깃 EC2 (/var/log/auth.log)]
               │
               ▼ (CloudWatch Agent: PutLogEvents)
[CloudWatch Logs 그룹: /cloudshield/target/auth-log]
               │
               ▼ [구독 필터: [mon, day, timestamp, host, process, msg = "*Failed password*", ...]]
               │ (의심 키워드 불일치 정상 로그: 비용 0원 즉시 드롭)
               │ (의심 키워드 일치 공격 로그: Base64 + Gzip 압축 비동기 스트리밍)
               ▼
[Lambda 위협 분석 오케스트레이터 (클라우드 A)] ──▶ [Boto3 복합 차단] ──▶ [Slack 알림]
```

### 구독 필터 도입의 핵심 목적
1. **서버리스 호출 비용 최적화**: 정상적인 SSH 로그인, cron 작업, sudo 이벤트 등 모든 시스템 로그가 Lambda를 호출할 경우 발생하는 불필요한 인보케이션 비용 및 동시성(Concurrency) 낭비를 원천 차단합니다.
2. **파이프라인 처리 지연(Latency) 최소화**: CloudWatch 관리형 필터 엔진에서 1차 선별된 의심 이벤트만 압축 배치 형태로 전달하므로, Lambda의 연산 부하를 최소화하고 10초 이내 원자적 차단 목표를 달성할 수 있습니다.

---

## 2. 구독 필터 정의 파라미터 매트릭스 (클라우드 A Terraform 인터페이스)

클라우드 A의 인프라(`infra/`) Terraform 모듈에 반영할 파라미터 규격 명세입니다:

| 파라미터 명 (`HCL Attribute`) | 설정값 (`Value`) | 설명 및 제약조건 |
| :--- | :--- | :--- |
| `name` | `CloudShield-SSH-FailedPassword-Filter` | 구독 필터 식별자 |
| `log_group_name` | `/cloudshield/target/auth-log` | `amazon-cloudwatch-agent.json`의 수집 대상 로그 그룹명과 100% 일치 |
| `filter_pattern` | `[mon, day, timestamp, host, process, msg = "*Failed password*", ...]` | Syslog 공백 토큰 기반 의심 키워드 선별 패턴 |
| `destination_arn` | `aws_lambda_function.threat_orchestrator.arn` | 클라우드 A가 배포한 위협 분석 오케스트레이터 Lambda 함수 ARN |
| `distribution` | `ByLogStream` (선택적) | 로그 스트림별 배치 전달 분배 방식 |

---

## 3. 필터 패턴(Filter Pattern) 구문 분석 및 설계 근거 (Why)

### 3.1 패턴 구문
```text
[mon, day, timestamp, host, process, msg = "*Failed password*", ...]
```

### 3.2 토큰별 매핑 및 작동 원리
- `mon`, `day`, `timestamp`: Syslog 헤더의 월, 일, 시간 필드를 공백 단위로 매핑 (예: `Sep`, `03`, `14:20:01`).
- `host`: 로그 생성 인스턴스 호스트명 (예: `target-ec2`).
- `process`: 로깅 프로세스 명칭 및 PID 블록 (예: `sshd[12341]:`).
- `msg = "*Failed password*"`:
  - 6번째 필드 이후 시작되는 메시지 본문(`msg`)에 `Failed password` 구문이 포함되어 있는지 와일드카드(`*`) 매칭 수행.
  - SSH 무차별 대입(Brute-force) 시도 시 발생하는 `Failed password for invalid user ...` 및 `Failed password for root ...` 패턴을 포괄적으로 탐지.
- `...`: 메시지 뒤에 이어지는 가변 길이 잔여 필드(출발지 IP, 포트, 프로토콜 등) 전체 수용.

---

## 4. 모의 Lambda 환경 Gzip 페이로드 전달 및 디코딩 연계 원리

### 4.1 CloudWatch Logs -> Lambda 전달 페이로드 구조
CloudWatch Logs 구독 필터는 대상 Lambda를 호출할 때 네트워크 효율성을 위해 단일 JSON 객체 내 Base64 인코딩 및 Gzip 압축된 바이너리 스트림 형태로 이벤트를 전달합니다:

```json
{
  "awslogs": {
    "data": "H4sICAAAAAAC/6tW... (Base64 인코딩 + Gzip 압축 바이너리)"
  }
}
```

### 4.2 디코딩 및 로그 라인 추출 메커니즘 (`src/collector/cw_processor.py`)
Lambda 핸들러는 `cw_processor.decode_cw_logs()`를 호출하여 원본 로그 라인들을 복원합니다:

```python
# cw_processor.py 내부 디코딩 프로세스
# 1. Base64 디코딩 -> Gzip 압축 해제 -> JSON 역직렬화
cw_payload = CloudWatchLogsPayload.from_awslogs_data(payload["awslogs"]["data"])

# 2. logEvents 내의 개별 message 문자열 추출
log_messages = [event.message for event in cw_payload.logEvents]

# 3. 추출된 로그 라인은 보안 탐지 엔진으로 직결
# for line in log_messages:
#     event = SyslogAuthEvent.parse_line(line)
#     report = evaluate_rules(event)
```

---

## 5. 클라우드 A Terraform IaC 구현 가이드 (협업 참고 코드)

클라우드 A 플랫폼 엔지니어가 `infra/` 모듈에 즉시 적용할 수 있는 Terraform 리소스 정의 예시입니다:

```hcl
# 1. CloudWatch Logs 구독 필터 정의
resource "aws_cloudwatch_log_subscription_filter" "ssh_failed_password" {
  name            = "CloudShield-SSH-FailedPassword-Filter"
  log_group_name  = "/cloudshield/target/auth-log"
  filter_pattern  = "[mon, day, timestamp, host, process, msg = \"*Failed password*\", ...]"
  destination_arn = aws_lambda_function.threat_orchestrator.arn

  depends_on = [
    aws_lambda_permission.allow_cloudwatch_logs
  ]
}

# 2. CloudWatch Logs의 Lambda 호출 권한 허용 (필수)
resource "aws_lambda_permission" "allow_cloudwatch_logs" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.threat_orchestrator.function_name
  principal     = "logs.${var.aws_region}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.target_auth_log.arn}:*"
}
```

---

## 6. 단위 테스트 및 검증 결과

`tests/unit/test_collector.py`에 다음 검증 테스트가 작성되었으며 100% 통과했습니다:

1. `test_decode_cw_logs_success`: 실제 Gzip 압축 페이로드(`mock_cw_event.json`)로부터 `Failed password` 로그 정상 복원 검증.
2. `test_decode_cw_logs_empty_events`: 빈 이벤트 목록 인입 시 예외 없이 빈 리스트 반환 검증.
3. `test_decode_cw_logs_invalid_inputs`: 잘못된 타입, 키 누락, 손상된 Base64/Gzip 데이터에 대한 방어적 예외 처리 검증.
4. `test_subscription_filter_parameters_contract`: 정의된 파라미터가 `amazon-cloudwatch-agent.json`의 로그 그룹명과 정확히 일치하는지 정적 단언.
5. `test_matches_subscription_filter_simulation`: 공격 로그(매칭 성공)와 정상 로그(필터 제외)의 로컬 시뮬레이션 동작 검증.
6. `test_mock_lambda_subscription_filter_pipeline`: 수집 $\rightarrow$ 필터 선별 $\rightarrow$ Gzip 인코딩 $\rightarrow$ Lambda 디코딩 $\rightarrow$ `SyslogAuthEvent` 계약 파싱까지 E2E 연계 무결성 100% 검증.
