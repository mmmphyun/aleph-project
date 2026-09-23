# [클라우드 B] 통합 오케스트레이터 연계 Slack 알림 페이로드 규격 및 예외 격리 명세서

- **작성일**: 2026-09-23
- **작성자**: 클라우드 B 담당 (`@wkdtlgns99-cell`)
- **연계 티켓**: [#73 통합 오케스트레이터 연계 Slack 알림 페이로드 규격 검증 및 예외 격리 보완](https://github.com/mmmphyun/aleph-project/issues/73)
- **1차 리뷰어**: 네트워크 담당 (`@RockCandy444`)

---

## 1. 개요 및 배경 (Why)

CloudShield의 핵심 프로젝트 정체성은 **"단일 10초 관통 자동 대응 파이프라인"**입니다.
타깃 EC2에서 수집된 SSH 인증 실패 이벤트가 CloudWatch Logs를 거쳐 Lambda 오케스트레이터(`threat_orchestrator_handler`)로 인입되면, DynamoDB 5분 슬라이딩 윈도우 누적 평가 후 L4 SG 격리 및 L7 WAF 차단이 즉각 집행됩니다.

인프라 차단 조치가 완료된 후, 관제 센터(SecOps) 채널로 상황을 전파하는 전파 모듈(`slack_notifier.py`)은 다음 두 가지 엔지니어링 요구사항을 충족해야 합니다:
1. **차단 조치 집행 결과 가시화**: 단순 탐지 경보(`IncidentReport`)뿐 아니라 실제 인프라 계층에서 집행된 다중 계층 차단 결과(`RemediationResult`)를 결합하여 Slack 카드로 렌더링.
2. **10초 관통 SLA 보장을 위한 3초 타임아웃 및 예외 격리(Fault Isolation)**: 전체 파이프라인의 10초 SLA를 준수하기 위해 Webhook 요청 상한을 3초로 강제하고, Slack API 장애나 일시 네트워크 단절이 발생하더라도 인프라 차단 트랜잭션과 오케스트레이터 런타임이 중단(Crash)되지 않도록 완전 격리.

---

## 2. 데이터 인터페이스 계약 연계 명세

### 2.1 다중 계층 차단 결과 모델 (`RemediationResult`)
클라우드 A 차단 엔진(`remediation.py`) 및 오케스트레이터(`orchestrator.py`)와 공유하는 TypedDict 인터페이스 규격입니다.

```python
class RemediationResult(TypedDict):
    waf_blocked: bool  # L7 AWS WAFv2 IPSet /32 등록 차단 성공 여부
    quarantine_applied: bool  # L4 EC2 Quarantine SG 원자적 교체 성공 여부
    iam_revoked: bool  # Identity IAM 임시 세션 무효화 성공 여부 (SSH 시나리오 제외)
```

### 2.2 `build_slack_payload` 확장 레이아웃
`remediation_result`가 전달될 경우, 기존 4대 필수 식별자 섹션에 더해 **"인프라 원자적 차단 집행 현황"** 섹션 블록이 동적으로 생성됩니다.

```json
{
  "type": "section",
  "text": {
    "type": "mrkdwn",
    "text": "*인프라 원자적 차단 집행 현황:*\n• L4 EC2 네트워크 격리: ✅ 격리 성공 (SG 전면 차단)\n• L7 WAFv2 IP 차단: ✅ IPSet 차단 완료 (/32)\n• Identity IAM 세션 무효화: ℹ️ 미적용 (SSH 시나리오 제외)"
  }
}
```

- 모든 텍스트 블록은 Slack Block Kit API 제약조건(섹션 필드 2,000자, 일반 텍스트 3,000자) 및 프로젝트 헌법 5.1-3(표시 문자열 500자 상한)에 따라 `truncate_text(..., 500)`를 통과합니다.
- 반환 딕셔너리에 4대 필수 키(`incident_id`, `rule_name`, `source_ip`, `remediation_action`) 및 `remediation_result` 구조화 데이터가 안전하게 포함됩니다.

---

## 3. 네트워크 타임아웃 및 결함 격리(Fault Isolation) 설계

### 3.1 3초 타임아웃 강제 (SLA Protection)
- 기존 기본 타임아웃 `5.0초` $\rightarrow$ **`3.0초` 단축**
- **근거**: 전체 E2E 파이프라인의 허용 시간은 10초입니다. 로그 수집(2~3초) + Lambda 구동 및 L4/L7 차단(2~3초)을 감안할 때, 알림 전파 단계에 허용 가능한 최대 지연 시간은 3초입니다.

### 3.2 일시 장애 재시도 및 예외 전파 차단 매트릭스

| 장애 유형 | HTTP 코드 / 예외 | 처리 전략 | 비고 |
| :--- | :--- | :--- | :--- |
| **클라이언트 오류** | HTTP 400, 403, 404, 429 | 재시도 없이 즉시 `False` 반환 | 페이로드/URL 오류로 재시도 무의미 |
| **서버 일시 장애** | HTTP 500, 502, 503, 504 | 1회 안전 재시도(`retry_delay=0.5s`) 후 소진 시 `False` | Slack 서버 일시적 순단 대응 |
| **요청 시간 초과** | `TimeoutError`, `socket.timeout` | 에러 로깅 후 즉시 `False` 반환 | 3초 이상 블로킹 방지 |
| **네트워크 단절** | `urllib.error.URLError` | 에러 로깅 후 1회 재시도, 최종 `False` | DNS 일시 오류 등 방어 |
| **기타 미처리 예외** | `Exception` | 에러 로깅 후 안전하게 `False` 반환 | 람다 런타임 비정상 종료 원천 차단 |

---

## 4. 검증 결과 요약

- `test_build_slack_payload_with_remediation_result_success`: L4/L7 차단 성공 마크다운 렌더링 검증 통과
- `test_build_slack_payload_with_partial_remediation_failure`: 미적용/실패 상태 렌더링 검증 통과
- `test_send_slack_alert_default_timeout_is_three_seconds`: 3.0초 타임아웃 인자 전달 검증 통과
- `test_send_slack_alert_transient_5xx_retry_and_recovery`: 503 오류 시 1회 재시도 후 200 성공 검증 통과
- `test_send_slack_alert_5xx_retry_exhausted_isolation`: 500 오류 시 재시도 소진 후 예외 없이 `False` 반환 검증 통과
- `test_send_slack_alert_client_4xx_no_retry`: 400 Bad Request 시 재시도 없이 1회 만에 즉시 `False` 반환 검증 통과
- `test_send_slack_alert_orchestrator_integration_mock`: 오케스트레이터 IncidentReport + RemediationResult 실 모의 데이터 연계 무결성 검증 통과
