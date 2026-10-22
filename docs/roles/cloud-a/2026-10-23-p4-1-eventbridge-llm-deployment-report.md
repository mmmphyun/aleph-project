# [P4-1] EventBridge 및 비동기 LLM 분석 파이프라인 실인프라 배포 및 E2E 테스트 보고서

- **작성 일시**: 2026-10-23 KST
- **작성자**: 클라우드 A (플랫폼 전담 @mmmphyun)
- **관련 티켓**: [P4-1] [클라우드 A] EventBridge 및 비동기 LLM 분석 파이프라인 실인프라 배포 및 E2E 테스트 (https://notion.so/3fe04d37c22580c38421c4f6c5793716)
- **관련 Issue / PR**: Issue #211
- **배포 리전**: `ap-southeast-2` (시드니)

---

## 1. 개요 및 배경

CloudShield의 핵심 아키텍처 원칙은 **10초 SLA를 갖는 실시간 긴급 차단(L4 SG / L7 WAF)** 경로와 **수십 초가 소요되는 Amazon Bedrock 기반 LLM 사후 심층 분석**의 물리적/아키텍처적 비동기 분리(Asynchronous Decoupling)입니다.

본 티켓에서는 Wave 1·2에서 모듈화된 EventBridge 규칙(`cloudshield-threat-remediated-dev`), 비동기 분석 워커(`cloudshield-llm-analyzer`), Bedrock/Slack 최소 권한 IAM 정책의 실인프라 정합성을 검증하고, 시나리오 1(SSH) 및 시나리오 2(Web) 위협에 대해 1차 즉시 차단 -> EventBridge 이벤트 발행 -> 2차 LLM 분석 워커 호출 -> 2차 Slack Block Kit 카드 전파로 이어지는 종단 간(E2E) 비동기 파이프라인 관통을 입증하였습니다.

---

## 2. 배포 및 아키텍처 리소스 명세

| 계층 | 리소스 명칭 | 유형 / 식별자 | 비고 및 SLA |
| :--- | :--- | :--- | :--- |
| **Event Routing** | EventBridge Rule | `cloudshield-threat-remediated-dev` | Pattern: `source=["cloudshield.security"]`, `detail-type=["ThreatRemediated"]` |
| **Worker Runtime** | Lambda Function | `cloudshield-llm-analyzer` | Python 3.12, 256MB, Timeout 30s, Max Retry 0 |
| **AI Engine** | Amazon Bedrock | `apac.amazon.nova-micro-v1:0` | Converse API 기반 정형 침해 리포트 생성 및 JSON 파싱 |
| **Reporting** | Slack Notifier | 2차 심층 분석 Webhook 전파 | `send_deep_analysis_slack_alert` 결함 격리 |
| **Packaging** | Lambda Bundle | `orchestrator.zip` (2.73MB) | 1차 오케스트레이터 및 2차 LLM 워커 공통 번들 |

### 2.1 보안 및 IAM 최소 권한 정책
- **CloudWatch Logging**: `/aws/lambda/cloudshield-llm-analyzer` 로그 그룹 한정 쓰기 권한.
- **Bedrock InvokeModel**: `arn:aws:bedrock:*::foundation-model/*` 및 현재 리전 inference-profile 한정 허용.
- **X-Ray Active Tracing**: 분산 추적 세그먼트 기록 권한 허용.
- **Zero Wildcard & Re-try Guard**: EventBridge Target의 `maximum_retry_attempts = 0` 설정을 통해 Bedrock 타임아웃/오류 시 재시도 폭풍(Throttling 폭포)을 원천 차단함.

---

## 3. 정적 보안 감사 및 IaC 검증 결과

1. **Lambda 아티팩트 빌드 (`scripts/package_lambda.py`)**:
   - `src/remediation/orchestrator.py`, `src/remediation/llm_worker.py`, `src/detection/llm_deep_analyzer.py`, `src/reporter/slack_notifier.py` 및 의존성 패키징 완료.
   - 아티팩트: `infra/terraform/modules/lambda/build/orchestrator.zip` (2,732,318 bytes).
2. **Trivy IaC 보안 감사 (`trivy config infra/terraform/modules/lambda`)**:
   - HIGH / CRITICAL 보안 결함 0건 (클린).
   - `main.tf`의 루트 Terraform 구문 유효성 검사(`terraform validate`) 100% 통과.

---

## 4. E2E 통합 관통 테스트 결과 (`tests/unit/`)

시나리오 1(SSH Brute Force) 및 시나리오 2(Web Path Traversal)에 대해 1차 차단부터 2차 비동기 LLM 워커 처리까지의 전체 체인을 단일 트랜잭션으로 검증하는 E2E 테스트를 신설하였습니다.

### 4.1 시나리오 1 검증 (`test_e2e_scenario1_async_eventbridge_to_llm_worker_pipeline`)
- **입력**: 5회 연속 SSH 비밀번호 실패 로그.
- **1차 실시간 대응**:
  - `threat_orchestrator_handler` 처리 완료 (`threats_detected == ["SSH_BRUTE_FORCE"]`).
  - L4 EC2 격리 SG 교체(`quarantine_applied=True`) 및 L7 WAF IPSet 차단(`waf_blocked=True`).
  - 1차 Slack 긴급 차단 알림 전파 완료.
- **EventBridge 비동기 연동**:
  - `Source: cloudshield.security`, `DetailType: ThreatRemediated` 이벤트 자동 발행 검증.
- **2차 사후 분석 워커**:
  - `llm_analysis_handler` 이벤트 수신 (`status: accepted`).
  - Bedrock Converse API를 통한 심층 분석 수행 (`llm_analyzed: True`).
  - 2차 심층 분석 Slack Block Kit 알림 카드 전파 완료 (`slack_notified: True`).

### 4.2 시나리오 2 검증 (`test_e2e_scenario2_async_eventbridge_to_llm_worker_pipeline`)
- **입력**: Web L7 Path Traversal (`/../../etc/passwd`) 단발성 침해 로그.
- **1차 실시간 대응**:
  - WAFv2 IPSet 공격자 IP/32 차단 집행 (`waf_blocked=True`).
  - 1차 Slack 알림 전파 및 EC2 가용성 보존(SG 변경 없음).
- **EventBridge 비동기 연동 & 2차 워커**:
  - `ThreatRemediated` 이벤트 수신 -> Bedrock 심층 권고사항 생성 -> 2차 Slack 카드 전파 성공.

---

## 5. 후속 직무(클라우드 B `[P4-2]`, 네트워크 `[P4-3]`) 실측 연계 가이드

1. **클라우드 B (`[P4-2]` Slack 1차·2차 전파 지연 실측)**:
   - 본 `[P4-1]` 배포로 인프라에 `ThreatRemediated` EventBridge 규칙과 `cloudshield-llm-analyzer` 워커가 활성화되었습니다.
   - 타깃 EC2에 위협 로그 인입 시, SecOps Slack 채널에 도착하는 1차 긴급 차단 카드와 2차 LLM 분석 카드의 Slack 메시지 타임스탬프(`ts`) 델타($\Delta t$)를 측정하여 실측 보고서를 작성하십시오.
2. **네트워크 (`[P4-3]` 최종 쇼케이스 왕복 관통 검증)**:
   - Kali Linux 환경에서 원클릭 통합 공격 러너를 구동하고, L4/L7 차단 집행 및 Slack 연속 전파 후 `scripts/restore_baseline_sg.py` 및 `scripts/unblock_waf_ip.py`를 통한 원복 무결성을 최종 실측하십시오.
