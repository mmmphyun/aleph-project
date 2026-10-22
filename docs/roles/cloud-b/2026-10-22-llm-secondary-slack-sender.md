# 2차 심층 분석 Slack Webhook 전송 함수 및 예외 격리

- Notion Task: https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0?p=3fe04d37c225807980c7e5a1e50edb5f&pm=c
- 직무: 클라우드 B
- 관련 이슈: https://github.com/mmmphyun/aleph-project/issues/209
- 관련 브랜치: `feat/cloud-b-llm-slack-sender`

---

## 1. 개요 및 목적

사후 LLM 심층 분석 결과(`IncidentReport`)를 SecOps 관리자 채널에 전파하는
`send_llm_slack_alert()` 전송 함수를 구축하고, 네트워크 지연 및 외부 장애에 대한
완전한 예외 격리(Fault Isolation) 단위 테스트를 확보한다.

- `from reporter import send_llm_slack_alert`로 가져와 검증된 사후 분석 `IncidentReport`를 전달한다.
- 1차 긴급 차단 알림(`send_slack_alert`)과 2차 심층 분석 알림(`send_llm_slack_alert`)의 R&R을 명확히 분리하고 인터페이스를 일관성 있게 표준화한다.

---

## 2. 핵심 동작 원리 (3대 원칙)

1. **시간 예산(Remaining Time Budget) 엄수**: 기본 3.0초 타임아웃 예산 내에서 단일/재시도 네트워크 요청 타임아웃을 동적으로 차감 계산하여 CloudShield 10초 관통 SLA 지연을 방어한다.
2. **응답 코드별 에러 분기 및 멱등 재시도**: HTTP 4xx 클라이언트 에러는 재시도 없이 즉시 실패(`False`) 처리하고, HTTP 5xx 서버 에러 및 일시 네트워크 단절에 한해 예산 범위 내에서 `max_retries`회 재시도한다.
3. **완전한 예외 격리 (Fault Isolation)**: Webhook URL 미설정, 비HTTPS 스킴, 파싱 에러, 타임아웃, 예기치 않은 시스템 예외 인입 시 호출자에게 결함이 전파되지 않도록 로깅 후 `False`를 반환하여 분석 파이프라인의 안전한 수명주기를 보장한다.

---

## 3. 검증 결과

- `tests/unit/test_reporter.py`에 12개 신규 단위 테스트 추가 (총 125개 테스트 100% 통과).
  - Webhook URL 미설정 및 빈 문자열 조기 반환 검증
  - 비HTTPS 스킴 및 비정상 IPv6 URL 입력 격리 검증
  - 정상 200 응답 및 `is_llm_card: True` 직렬화 전송 검증
  - `SLACK_WEBHOOK_URL` 환경변수 Fallback 검증
  - HTTP 4xx 무재시도 즉시 종료 검증
  - HTTP 5xx 일시 장애 후 성공 복구 및 재시도 초과 격리 검증
  - `TimeoutError` 및 `URLError(timed out)` 즉시 종료 검증
  - 네트워크 단절(`URLError`) 재시도 후 격리 검증
  - 예기치 않은 시스템 예외 격리 검증
  - 타임아웃 시간 예산 소진 시 재시도 생략 검증
- R&R 스코프 검사 통과 (`scripts/verify_rnr_scope.py`).
- Ruff Lint & Format 검사 통과.
