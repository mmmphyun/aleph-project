# [클라우드 A] 통합 오케스트레이터-Slack 파이프라인 결합 및 결함 격리(Fault Isolation) 아키텍처 명세서

- **작성일**: 2026-09-28
- **작성자**: 클라우드 A 담당 (`@mmmphyun`)
- **연계 티켓**: [#79 오케스트레이터 내 Slack 알림 연동 및 통합 차단 파이프라인 결합](https://github.com/mmmphyun/aleph-project/issues/79)
- **연관 PR**: [#80 feat(cloud-a): 오케스트레이터 내 Slack 알림 연동 및 통합 차단 파이프라인 결합](https://github.com/mmmphyun/aleph-project/pull/80)
- **1차 리뷰어**: 클라우드 B 담당 (`@wkdtlgns99-cell`)

---

## 1. 개요 및 배경 (Why)

CloudShield의 핵심 프로젝트 목표는 **"10초 관통 단일 침해사고 자동 대응 파이프라인"**의 무결성 증빙입니다.
타깃 EC2에서 발생한 SSH 무차별 대입(Brute Force) 공격 로그가 CloudWatch Logs 구독 필터를 통해 Lambda 오케스트레이터(`threat_orchestrator_handler`)로 인입되면, DynamoDB 5분 누적 슬라이딩 윈도우 평가를 거쳐 L4 Security Group 전면 격리와 L7 AWS WAFv2 IPSet /32 차단이 원자적으로 집행됩니다.

인프라 차단 조치가 완료된 후 SecOps 관리자 채널로 상황을 실시간 전파하는 Slack Webhook 모듈(`send_slack_alert`)을 결합할 때, 다음 두 가지 분산 시스템 트랜잭션 과제가 발생합니다:
1. **비대칭 트랜잭션 경계 분리**: 외부 서드파티 통지(Slack)의 장애가 사전에 완료된 클라우드 보안 차단 상태를 롤백하거나 전체 런타임을 중단(Crash)시키지 않도록 완전한 결함 격리(Fault Isolation)를 강제해야 함.
2. **10초 관통 SLA 준수를 위한 시간 예산(Time Budget) 분배**: 외부 네트워크 I/O의 블로킹 지연으로 인해 전체 E2E 대응 시간이 10초를 초과하지 않도록 3.0초 하드 타임아웃을 강제해야 함.

---

## 2. 비대칭 트랜잭션과 결함 격리(Fault Isolation) 설계

### 2.1 인프라 상태 변경(State Mutation) vs 외부 통지(Notification)
- **AWS API 트랜잭션**:
  - `ec2:ModifyInstanceAttribute`(Quarantine SG 교체) 및 `wafv2:UpdateIPSet`(공격자 IP 등록)은 AWS 하이퍼바이저와 패킷 필터링 계층에 영구 반영되는 상태 변경 작업입니다.
  - 이 조치는 RDBMS의 분산 트랜잭션 매니저(2PC 등)로 묶여 있지 않으므로, 상위 파이썬 프로세스에서 예외가 발생하더라도 AWS가 자동으로 이전 상태로 롤백해 주지 않습니다.
- **외부 통지 I/O의 비결정론적 특성**:
  - Slack Incoming Webhook은 외부 인터넷 망을 통과하는 단방향 HTTP POST 요청입니다.
  - Slack API 서버 장애(500, 502, 503), 네트워크 패킷 유실, DNS 질의 실패, TLS 협상 타임아웃 등 통제 불가능한 런타임 장애에 항상 노출되어 있습니다.

### 2.2 실패 원자성(Failure Atomicity) 및 보안 Fail-Closed 원칙
- **격리 매커니즘**:
  - `orchestrator.py`는 `apply_remediation()` 실행 및 DynamoDB `quarantined=True` 마킹이 완료된 이후에만 `send_slack_alert()`를 호출합니다.
  - 호출부는 엄격한 `try-except Exception` 블록으로 래핑되어 있어, Webhook 호출 과정에서 `HTTPError`, `TimeoutError`, 소켓 예외가 발생하더라도 이를 로깅하고 삼켜(Suppress) 상위 런타임으로 예외가 누출되지 않도록 차단합니다.
- **보안 연속성 보장**:
  - 알림이 실패하더라도 침해 서버는 이미 L4 격리 및 L7 차단 상태를 유지합니다.
  - "알림 실패로 인해 차단이 풀리거나 시스템이 죽는 최악의 보안 사각지대"를 원천 방지합니다.

```text
[CloudWatch Logs 인입]
         │
         ▼
[DynamoDB 누적 윈도우 평가] ──(임계치 5회 도달)──┐
                                               ▼
                                 [Boto3 원자적 인프라 차단]
                                 ├── L4 EC2 Quarantine SG 교체
                                 └── L7 WAFv2 IPSet /32 차단
                                               │
                                               ▼ (성공 확인)
                                 [DynamoDB 원자적 격리 마킹]
                                 └── target_key: quarantined=True
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       ▼                                               ▼
         [Slack Webhook 전송 성공]                        [Slack Webhook 실패/지연/5xx]
         ├── HTTP 200 수신                                ├── TimeoutError / HTTPError 발생
         └── slack_notified = True                        ├── try-except 예외 완전 격리
                                                          ├── L4/L7 차단 및 마킹 유지 (롤백 불가)
                                                          └── slack_notified = False
                       │                                               │
                       └───────────────────────┬───────────────────────┘
                                               ▼
                                  [최종 통합 결과 딕셔너리 반환]
```

---

## 3. 10초 관통 SLA와 E2E 레이턴시 예산(Time Budget)

### 3.1 단계별 지연 시간(Latency) 허용 한계

| 처리 단계 | 상세 동작 | 예상 지연 시간 | 누적 시간 |
| :--- | :--- | :--- | :--- |
| **1. 수집 (Collector)** | 타깃 EC2 커널 로그 버퍼 플러시 및 CW Agent 전송 | 2.0 ~ 3.0초 | 3.0초 |
| **2. 인입 (Filter)** | CloudWatch Logs Subscription Filter $\rightarrow$ Lambda 호출 | 1.0 ~ 1.5초 | 4.5초 |
| **3. 윈도우 평가 (State)** | Lambda 콜드/웜 기동 및 DynamoDB 3-버킷 읽기/쓰기 RTT | 0.5 ~ 1.0초 | 5.5초 |
| **4. 차단 (Remediation)** | AWS EC2 / WAFv2 Boto3 API RTT (병렬/직렬 호출) | 1.0 ~ 1.5초 | 7.0초 |
| **5. 전파 (Reporter)** | Slack Incoming Webhook HTTP POST 전송 (Hard Limit) | **최대 3.0초** | **10.0초 (SLA 충족)** |

### 3.2 소켓 블로킹 제어
- Linux 커널의 기본 TCP SYN 재전송 타이머(SYN Retries)는 기본 5회 이상, 수십 초간 블로킹을 유발할 수 있습니다.
- `slack_notifier.py`는 `monotonic clock` 기반의 시간 예산(Time Budget)을 추적하며, 단일 타임아웃 및 재시도 대기 시간을 3.0초 이내로 엄격히 제한하여 상위 파이프라인의 결정론적 종료(Bounded Latency)를 보장합니다.

---

## 4. 응답 계약 확장 및 멱등성 보장

### 4.1 `slack_notified` 반환 필드 규격
- `threat_orchestrator_handler` 반환 딕셔너리에 불리언 필드 `slack_notified`를 추가했습니다.
- **판정 로직 (`all()`)**:
  - 단일 배치 내 복수의 위협이 탐지된 경우, 모든 위협 통지가 100% 성공했을 때만 `True`를 반환합니다.
  - 단 1건이라도 알림이 누락되었다면 보안 관제상 '부분 실패(Partial Failure)'로 간주하여 `False`를 반환함으로써 운영 사각지대를 방지합니다.
  - 위협이 탐지되지 않은 정상/경미 로그 배치는 불필요한 알림 발송 없이 기본값 `False`를 유지합니다.

### 4.2 멱등성(Idempotency) 및 후속 배치 재시도 억제
- 차단 성공 후 DynamoDB 버킷 레코드에 `quarantined: True`가 기록되므로, 동일 공격자의 후속 실패 로그 배치가 인입되더라도 `check_threat()`에서 위협 판정이 차단됩니다.
- 이에 따라 중복된 Boto3 차단 호출과 중복 Slack 알림 발송이 원천 억제됩니다.

---

## 5. Shift-Left 사전 검증(CI) vs 런타임 인프라 위험 매트릭스

장애 발생 시 책임 소재 규명과 빠른 복구를 위해, CI 파이프라인에서 100% 검증된 영역과 실제 AWS 배포 시 점검해야 할 인프라 위험 영역을 다음과 같이 분리 정의합니다.

### 5.1 CI/단위 테스트에서 100% 방어 완료된 영역 (코드 결함 불가)
- **테스트 슈트 (`tests/unit/test_remediation.py`)**:
  - `test_threat_orchestrator_slack_integration_success`: L4/L7 차단 성공 및 Slack 알림 전파 정상 연계 검증.
  - `test_threat_orchestrator_slack_failure_fault_isolation`: Webhook 타임아웃/예외 발생 시 차단 유지 및 마킹 롤백 방지 검증.
  - `test_threat_orchestrator_slack_no_webhook_url`: 환경 변수 미설정 시 안전한 비활성화 검증.
  - `test_threat_orchestrator_slack_no_threat_defaults_to_false`: 임계치 미달 시 기본값 검증.
  - `test_threat_orchestrator_slack_env_var_fallback`: `SLACK_WEBHOOK_URL` 환경 변수 우선순위 폴백 검증.

### 5.2 실제 AWS 배포 시 점검 대상 인프라 체크리스트 (IaC/런타임 영역)
머지 후 알림 누락 또는 실행 실패가 발생할 경우, 소스 코드가 아닌 다음 3대 인프라 레이어를 우선 점검합니다:

1. **VPC NAT Gateway 및 아웃바운드 라우팅 (Network Topology)**:
   - 오케스트레이터 Lambda가 타깃 EC2와 동일한 Private Subnet에 배치된 경우, 외부 인터넷(`hooks.slack.com:443`)으로 라우팅되는 NAT Gateway가 없으면 패킷 드롭으로 3.0초 타임아웃 고착 발생.
2. **Lambda 환경 변수 및 시크릿 주입 (Configuration)**:
   - Terraform 또는 CI/CD 배포 스크립트에서 `SLACK_WEBHOOK_URL` 환경 변수가 올바른 HTTPS 엔드포인트로 설정되어 있는지 점검.
3. **AWS IAM 실행 권한 (IAM Execution Role)**:
   - Lambda 실행 역할에 `ec2:ModifyInstanceAttribute`, `ec2:DescribeInstances`, `wafv2:GetIPSet`, `wafv2:UpdateIPSet` 정책이 누락되어 발생하는 `AccessDeniedException` 여부 점검.
