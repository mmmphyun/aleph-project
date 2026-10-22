# 2차 심층 분석 Slack Webhook 전송 함수 및 예외 격리

- Notion Task: https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0?p=3fe04d37c225807980c7e5a1e50edb5f&pm=c
- 직무: 클라우드 B
- 관련 이슈: https://github.com/mmmphyun/aleph-project/issues/209
- 관련 PR: https://github.com/mmmphyun/aleph-project/pull/210
- 관련 브랜치: `feat/cloud-b-llm-slack-sender`

---

## 1. 개요 및 목적

사후 LLM 심층 분석 결과(`IncidentReport`)를 SecOps 관리자 채널에 전파하는
`send_llm_slack_alert()` 전송 함수를 구축하고, 네트워크 지연 및 외부 장애에 대한
완전한 예외 격리(Fault Isolation), 엄격한 전체 Deadline 집행 및 Bounded 자원 관리 단위 테스트를 확보한다.

- `from reporter import send_llm_slack_alert`로 가져와 검증된 사후 분석 `IncidentReport`를 전달한다.
- 1차 긴급 차단 알림(`send_slack_alert`)과 2차 심층 분석 알림(`send_llm_slack_alert`)의 R&R을 명확히 분리하고 인터페이스를 일관성 있게 표준화한다.

---

## 2. 핵심 동작 원리 (3대 원칙)

1. **전체 Deadline(3.0초) 단일 예산 엄격 집행 및 세마포어 대기 시간 차감**:
   - 세마포어 자원 획득 대기와 실제 네트워크 전송이 **단일한 잔여 시간 예산(`remaining_budget`)**을 공유하도록 구현한다.
   - `_SLACK_REQUEST_SEMAPHORE.acquire()` 직후 원래 `start_time` 기준 경과 시간을 즉시 재계산하여 잔여 예산에서 차감하며, 슬롯 대기 중 deadline이 소진된 경우(`remaining_budget <= 0`) 새 전송 스레드를 시작하지 않고 획득한 슬롯을 즉시 반환(`release()`) 후 조기 종료한다.
   - 워커의 소켓 타임아웃과 완료 대기(`req_done.wait()`)에도 대기 시간이 차감된 순수 잔여 예산만 부여하여, 경합 상황에서도 총 소요 시간이 deadline을 절대로 초과하지 않도록 보장한다.
   - `MAX_CONCURRENT_SLACK_REQUESTS(2)` 상한선으로 동시 실행 자원을 엄격히 통제하고, `cancel_event`로 만료된 연결을 정리하며, 스레드 시작 실패(`RuntimeError`) 시에도 슬롯을 회수하고 안전 격리한다.
2. **응답 코드별 에러 분기 및 멱등 재시도**:
   - HTTP 4xx 클라이언트 에러는 재시도 없이 즉시 실패(`False`) 처리하고, HTTP 5xx 서버 에러 및 일시 네트워크 단절에 한해 잔여 예산 범위 내에서 `max_retries`회 재시도한다.
3. **요청 전 과정에서의 Webhook Secret 토큰 로그 노출 원천 차단**:
   - 사전 URL 검증뿐만 아니라 `urllib.request` / `http.client` 요청 처리 중 발생하는 모든 예외(`InvalidURL`, `HTTPError`, `URLError` 등)에서 URL 및 경로 인자 문자열을 일체 출력하지 않고 오류 타입명(`type(exc).__name__`)과 HTTP 상태 코드만 안전하게 기록하여, 경로 공백 등의 비정상 URL에서도 비밀 토큰이 CloudWatch 등에 유출되지 않도록 완전한 보안을 보장한다.

---

## 3. 검증 결과

- `tests/unit/test_reporter.py`에 20개 단위/회귀 테스트 확보 (총 133개 테스트 100% 통과).
  - Webhook URL 미설정 및 빈 문자열 조기 반환 검증
  - 비HTTPS 스킴 및 비정상 IPv6 URL 입력 격리 검증
  - 비HTTPS 및 URL 파싱 오류 경로에서 Webhook Secret 토큰 로그 미노출(마스킹) 검증
  - 정상 HTTPS이지만 경로에 공백이 있어 `InvalidURL`을 유발할 때 Webhook Secret 로그 미노출 회귀 검증
  - 정상 200 응답 및 `is_llm_card: True` 직렬화 전송 검증
  - `SLACK_WEBHOOK_URL` 환경변수 Fallback 검증
  - HTTP 4xx 무재시도 즉시 종료 검증
  - HTTP 5xx 일시 장애 후 성공 복구 및 재시도 초과 격리 검증
  - `TimeoutError` 및 `URLError(timed out)` 즉시 종료 검증
  - 네트워크 단절(`URLError`) 재시도 후 격리 검증
  - 느린 헤더 수신 누적 4초 지연 시 3초 deadline 집행 차단 검증
  - 실제 블로킹 소켓 I/O 지연 시 데몬 스레드 경계 빠른 탈출(Early Exit) 검증
  - 연속 타임아웃 발생 시에도 동시 실행 작업 수가 상한(2개) 이하로 유지되고 무한 증가하지 않음 검증
  - 스레드 시작 시 `RuntimeError` 발생 시 상위 전파 없이 `False` 안전 격리 검증
  - 세마포어 대기 도중 시간 예산 소진 시 전송 미시작 및 슬롯 즉시 반환 회귀 검증 (`test_send_llm_slack_alert_semaphore_acquire_budget_exhausted_releases_slot`)
  - 슬롯 대기 시간(0.10초)이 전체 deadline(0.20초)에서 차감되어 워커에 잔여 예산만 부여되고 총 소요 시간 초과가 방지됨을 검증 (`test_send_llm_slack_alert_semaphore_wait_deducted_from_overall_deadline`)
  - 예기치 않은 시스템 예외 격리 검증
  - 타임아웃 시간 예산 소진 시 재시도 생략 검증
- R&R 스코프 검사 통과 (`scripts/verify_rnr_scope.py`).
- Ruff Lint & Format 검사 통과.
- `powershell .\scripts\check.ps1` 전체 로컬 게이트 통과.
