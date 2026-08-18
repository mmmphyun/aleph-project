# 공통 이벤트 형식

모든 탐지 소스는 내부 처리 전에 아래 형식으로 변환합니다. 실제 AWS 서비스 연동 전에는 이 형식의 Mock 이벤트를 사용합니다.

```json
{
  "event_id": "evt-001",
  "event_type": "iam.role_assume",
  "account_id": "workload-001",
  "principal": "developer-role",
  "source_ip": "203.0.113.10",
  "resource": "production-admin",
  "severity": "high",
  "occurred_at": "2026-08-18T12:00:00Z",
  "raw_event": {}
}
```

## 필드 규칙

| 필드 | 필수 | 설명 |
|---|---|---|
| `event_id` | 예 | 이벤트를 식별하는 고유값 |
| `event_type` | 예 | 이벤트 종류 |
| `account_id` | 예 | 이벤트가 발생한 AWS 계정 |
| `principal` | 예 | 작업을 수행한 사용자 또는 역할 |
| `source_ip` | 아니오 | 요청 출발지 IP |
| `resource` | 아니오 | 접근 또는 변경 대상 |
| `severity` | 예 | `low`, `medium`, `high`, `critical` 중 하나 |
| `occurred_at` | 예 | ISO 8601 형식의 발생 시각 |
| `raw_event` | 예 | 원본 이벤트 또는 Mock 데이터 |

이벤트 생성자는 원본 정보를 보존하고, 이후 모듈은 공통 필드에 의존합니다. 실제 AWS 연동으로 교체하더라도 이 입력·출력 계약은 유지합니다.
