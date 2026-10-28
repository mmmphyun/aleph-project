# 2차 LLM 보고서 멀티 블록 렌더러 및 3차 복구 알림 카드

- Notion Task: https://notion.so/40504d37c22581c38dadfadabb31adca
- 담당: 클라우드 B
- 범위: reporter 카드 빌더, 공개 API, reporter 단위 테스트

## 구현

`build_mrkdwn_sections(label, value, empty_value=...)`는 라벨을 포함한 텍스트를
500자 이하 section으로 나눈다. 원문을 순서대로 보존하며 `&`, `<`, `>`를
한 번만 이스케이프하고 엔티티 중간에서 분할하지 않는다.

`build_llm_slack_payload(report)`는 분석 요약, 대상 계정 목록, 번호가 붙은 권고
목록을 여러 블록에 보존한다. 사건 메타데이터와 fallback text에는 기존 500자
제한을 유지한다. 공백뿐인 요약에는 대체 문구를 사용하고, 내용이 있는 요약의
앞뒤 공백은 보존한다.

Slack 메시지는 최대 50블록이다. 이를 초과하면 `ValueError`로 명시적으로
실패하며 내용을 생략하거나 초과 페이로드를 전송하지 않는다. 기존
`send_llm_slack_alert`는 이 오류를 로그에 남기고 `False`를 반환한다.
여러 메시지로 나누어 전송하는 기능은 포함하지 않는다.

`build_recovery_slack_payload(report, recovery_result)`는 동일 사건 ID를 유지하고
기존 `apply_rollback` 반환 키를 소비한다.

| 대응 액션 | 필요한 복구 결과 |
| --- | --- |
| BLOCK_AND_QUARANTINE | quarantine_restored, waf_unblocked |
| QUARANTINE_EC2 | quarantine_restored |
| BLOCK_WAF / BLOCK_IP_ONLY | waf_unblocked |
| REVOKE_IAM_SESSION | iam_restored |
| NONE / ALERT_ONLY | 복구 미대상 |

필수 결과가 모두 정확한 `True`일 때만 설정 복구를 확인한다. `False`는 실패 또는
일부 미완료, 키 누락과 문자열/숫자 값은 미확인으로 표시한다. 미대상 계층은
성공으로 집계하지 않는다. `traffic_verified is True`가 전달된 경우에만 실제
통신 회복을 확인한다. `verification_status`, `t_restored_iso`, `details`는 선택
표시 정보이며 복구 성공을 대신 판정하지 않는다.

복구 카드는 페이로드 생성까지만 제공한다. 실제 복구 엔진 호출·플랫폼 전송 연결은
클라우드 A의 연계 범위다. 공통 계약, 복구 엔진, AWS 리소스는 변경하지 않는다.

## 검증 범위

긴 분석/권고 원문 보존, 이스케이프 경계, 원문 앞뒤 공백, 빈 값,
50블록 정확한 경계 및 초과, 잘못된 길이 상한, 계층별 부분 실패·결과 누락·
비불리언 성공값, 외부 입력 멘션, 복구 상세 `None`을 reporter 테스트로 검증한다.

참고: [Slack 메시지 블록 상한](https://docs.slack.dev/reference/block-kit/blocks/),
[Slack 텍스트 이스케이프](https://docs.slack.dev/messaging/formatting-message-text/#escaping-text).
