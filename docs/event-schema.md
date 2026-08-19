# 공통 이벤트 형식

모든 탐지 소스는 내부 처리 전에 아래 형식으로 변환합니다. 실제 AWS 서비스 연동 전에는 이 형식의 Mock 이벤트와 비식별화한 CloudTrail Fixture를 사용합니다.

```json
{
  "event_id": "evt-001",
  "event_type": "iam.role_assume",
  "event_source": "sts.amazonaws.com",
  "event_name": "AssumeRole",
  "account_id": "123456789012",
  "region": "ap-northeast-2",
  "principal": "developer-role",
  "session_name": "dev-session-001",
  "source_ip": "203.0.113.10",
  "user_agent": "aws-cli/2.x",
  "resource": "arn:aws:iam::123456789012:role/production-readonly",
  "outcome": "success",
  "occurred_at": "2026-08-18T12:00:00Z",
  "risk": {
    "severity": "high",
    "score": 85,
    "reasons": [
      "unusual_source_ip",
      "cross_account_role_assumption"
    ]
  },
  "raw_event": {}
}
```

## 처리 단계

```text
원본 이벤트
→ 정규화 이벤트
→ 위험도 평가
→ 대응 결정
```

수집기와 파서는 원본을 공통 형식으로 변환하지만 위험도를 최종 결정하지 않습니다. `risk`는 분석기가 계산하며, 규칙과 근거를 함께 기록합니다.

## 필드 규칙

| 필드 | 필수 | 설명 |
|---|---|---|
| `event_id` | 예 | 이벤트를 식별하는 고유값 |
| `event_type` | 예 | 내부 이벤트 종류 |
| `event_source` | 예 | 원본 AWS 서비스 |
| `event_name` | 예 | 원본 API 또는 이벤트 이름 |
| `account_id` | 예 | 이벤트가 발생한 AWS 계정 |
| `region` | 예 | 이벤트가 발생한 리전. 글로벌 서비스는 원본 값을 보존 |
| `principal` | 예 | 작업을 수행한 사용자 또는 역할 |
| `session_name` | 아니오 | 역할 세션 이름 |
| `source_ip` | 아니오 | 요청 출발지 IP |
| `user_agent` | 아니오 | 요청을 만든 도구 또는 클라이언트 |
| `resource` | 아니오 | 접근 또는 변경 대상 |
| `outcome` | 예 | `success`, `denied`, `error`, `unknown` 중 하나 |
| `occurred_at` | 예 | ISO 8601 형식의 발생 시각 |
| `risk` | 아니오 | 분석기가 계산한 점수·심각도·근거 |
| `raw_event` | 예 | 원본 이벤트 또는 Mock 데이터 |

`severity`는 원본 이벤트의 필드가 아니라 위험도 평가 결과입니다. 분석기는 점수와 판단 근거를 함께 기록해야 합니다.

## Fixture 규칙

`tests/fixtures/cloudtrail_samples/`에는 다음 이벤트를 비식별화해 저장합니다.

- `AssumeRole`
- `PutBucketAcl`
- `AuthorizeSecurityGroupIngress`

실제 계정 ID, ARN, IP, 사용자명, Access Key, Session Token은 저장하지 않습니다. 원본 구조가 필요한 경우에도 테스트용 값으로 치환합니다.
