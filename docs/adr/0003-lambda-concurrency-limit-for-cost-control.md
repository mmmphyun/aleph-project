# ADR 0003: LLM API 비용 폭증 방지를 위한 Lambda Reserved Concurrency 통제

- **상태**: 승인됨 (Accepted)
- **결정자**: 클라우드 A (테크 리드 @mmmphyun)
- **일자**: 2026-09-04
- **소유 직무**: 클라우드 A (인프라/비용 통제)

---

## 1. 배경 및 문제 제기 (Context)

- CloudShield 파이프라인은 침해 로그 인입 시 Lambda가 기동되어 정규식 룰 엔진 및 외부 LLM API(Anthropic Claude / OpenAI GPT)를 호출하여 `IncidentReport`를 생성함.
- 외부 공격자(Hydra 등)가 대규모 무차별 대입 공격을 초당 수백~수천 건 인입시킬 경우:
  - CloudWatch Logs Subscription Filter가 대량의 Lambda 인스턴스를 동시 기동(Auto-scale)함.
  - 외부 상용 LLM API 호출 수가 급증하여 분당 과금 폭증(API Billing Disaster) 및 외부 API Rate Limit(429 Too Many Requests) 초과 장애 발생 위험이 존재함.

---

## 2. 대안 검토 및 트레이드오프 분석 (Considered Options)

| 구분 | 방안 1: 기본 Lambda 동시성 (무제한 1,000) | 방안 2: Lambda Reserved Concurrency 제한 (채택) | 방안 3: SQS 지연 대기열 큐잉 |
| :--- | :--- | :--- | :--- |
| **비용 통제** | 비용 통제 불가 (LLM 과금 폭증 위험) | **동시 실행 상한을 5~10으로 강제하여 비용 완벽 통제** | 큐 인입으로 비용 제어 가능 |
| **시스템 복잡도** | 없음 (기본값) | Terraform 코드 1줄 설정 (`reserved_concurrent_executions = 5`) | SQS 대기열, DLQ, 재시도 오케스트레이션 추가로 복잡도 증가 |
| **실시간 대응 지연** | 없음 (동시 다발 실행) | 초과 호출 시 Throttling 발생 (1차 룰 탐지로 선제 차단하여 위험 경감) | 큐 폴링 지연으로 10초 관통 대응 목표 위배 가능 |

---

## 3. 아키텍처 결정 (Decision)

- **파이프라인 Lambda 함수의 `Reserved Concurrency`를 5~10으로 고정 제한**:
  - Terraform IaC 설정에서 분석 Lambda의 동시 실행 수를 최대 5(또는 10)로 제한함.
  - 고비용 LLM API 호출 빈도를 원천 제한하여 예상치 못한 대량 공격 유입 시에도 안전한 예산 상한선 보장.
  - 1차 선제 차단(WAF/SG)은 정규식 기반 초동 대응으로 즉시 수행하고, LLM 심층 분석 단계는 제한된 동시성 내에서 순차 처리되도록 보호함.

---

## 4. 기대 효과 및 결과 (Consequences)

- **긍정적 영향**:
  - LLM API 비용 폭증(Spike) 위험을 사전에 100% 방어.
  - 테스트 및 모의 공격 진행 중 실수로 인한 클라우드 청구 요금 사고 차단.
- **관리 대상 한계점**:
  - 대량 공격 지속 시 Lambda Throttling(429) 메트릭이 발생하므로, CloudWatch Alarm을 설정하여 스로틀링 발생 모니터링 필요.
