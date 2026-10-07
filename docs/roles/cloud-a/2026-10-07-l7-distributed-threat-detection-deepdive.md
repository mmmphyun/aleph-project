# Engineering Deep-Dive: AWS Lambda & DynamoDB 기반 L7 분산 위협 탐지 파이프라인 무결성 확보

## 1. 개요 (Overview)

본 문서는 Nginx L7 접근 로그 스트림에서 디렉터리 스캐닝 및 웹 침해 위협을 실시간 탐지하고 AWS WAFv2 IPSet에 원자적 차단을 집행하는 서버리스 관통 파이프라인(PR #134, #135)의 아키텍처 의사결정 및 분산 환경 결함 격리 과정을 기록한다.

CloudWatch Logs Subscription Filter를 통해 인입되는 비동기 분할 배치(Split-batch) 환경에서 Lambda의 무상태성(Stateless)과 분산 시스템 제약(물리적 스토리지 상한선, 복제 지연, 순서 역전)으로 인해 발생한 탐지 누락 문제를 단계별로 분석하고 해결한 엔지니어링 기록이다.

---

## 2. 아키텍처 다이어그램 (Architecture Workflow)

```
[ Nginx Access Log ]
        │
        ▼
[ CloudWatch Logs Subscription Filter ]
        │ (Base64 / Gzip Payload)
        ▼
[ Lambda: Threat Orchestrator ] 
        │
        ├── 1. IP별 분할 집계 & 시간순 정렬
        ├── 2. 분산 슬라이딩 윈도우 동기화 ──► [ DynamoDB: WebAttackWindow ]
        │      (Strongly Consistent Read)       (2-버킷 파티셔닝 + 슬롯 청킹)
        ├── 3. evaluate_web_rules (시그니처/임계치 투 포인터 평가)
        │
        ▼ (위협 탐지: IncidentReport 승격)
[ AWS WAFv2 IPSet ] ──► 원자적 /32 IP 차단
        │
        ▼ (Fault Isolation)
[ Slack Security Ops Channel ] (관제 알림)
```

---

## 3. 분산 환경의 핵심 기술 과제 및 해결 과정 (Deep-Dive)

### 3.1. 무상태(Stateless) 런타임 간 상태 공유 결함

* **문제 상황:** 초기 구현에서 공격 윈도우 집계(`WebAttackWindow`)를 Lambda 프로세스 메모리(`dict`)에 저장함. CloudWatch Logs가 동일 IP의 단일 공격 시퀀스(예: 4초 내 5회 404 스캔)를 3개, 2개로 분할 인입시키거나 서로 다른 Lambda 컨테이너로 라우팅할 경우 컨테이너 간 상태가 공유되지 않아 탐지 누락(차단 0회) 발생.
* **해결 방법:** 중앙 분산 저장소로 Amazon DynamoDB를 도입하여 타깃 및 IP 단위 집계 상태를 영속화하고, 독립 실행 환경 간에도 공격 이력이 누적되도록 아키텍처 전환.

### 3.2. 최소 권한(Least Privilege) IAM과 SDK 암묵적 호출 정합화

* **문제 상황:** Boto3 `dynamodb.Table(...)` 리소스 모델 초기화 시 내부적으로 `DescribeTable` API(`Table.load()`)가 암묵적으로 호출됨. Lambda 실행 역할에는 최소 권한 원칙에 따라 데이터 플레인 권한(`GetItem`, `PutItem`, `UpdateItem`, `DeleteItem`)만 부여되어 있어 `AccessDenied` 예외가 발생. 이를 핸들러 내부의 광범위 예외 처리(`except Exception`)가 인메모리 폴백으로 자동 격리하면서 DynamoDB 영속화가 무음 비활성화(Silent Fallback)되는 결함 발생.
* **해결 방법:**
  - SDK 초기화 경로에서 불필요한 메타데이터 로드 호출(`Table.load()`)을 완전히 배제.
  - Terraform IAM 모듈(`infra/terraform/modules/lambda/main.tf`)의 인라인 정책에 대상 테이블 ARN 한정으로 `dynamodb:DescribeTable` 권한을 명시적으로 동기화하여 인프라-코드 정합성 확보.

### 3.3. 분산 복제 지연으로 인한 누락 방지 (Eventual vs Strong Consistency)

* **문제 상황:** 선행 Lambda 런타임이 기록한 최신 공격 이력이 DynamoDB 스토리지 노드 간 복제 지연(Eventual Consistency)으로 인해 후속 런타임의 기본 `get_item` 조회 결과에 즉시 반영되지 않아 임계치 미달로 탐지 누락 발생.
* **해결 방법:** `WebAttackWindow.get_active_events` 내 모든 DynamoDB 읽기 호출에 `ConsistentRead=True`를 강제 적용하여 최신 커밋 데이터 반환을 수학적으로 보장.

### 3.4. DynamoDB 단일 항목 크기 상한(400KB) 극복: 2-버킷 파티셔닝 & 슬롯 청킹

* **문제 상황:**
  - 동일 타깃/IP 키의 단일 `events` 리스트에 로그 원문을 무제한 `list_append`하는 구조로 인해, 트래픽이 집중되는 IP 항목이 DynamoDB 단일 항목 상한선인 400KB를 초과하여 `ValidationException` 발생. 이후 모든 쓰기가 거부되어 공격 탐지 영구 마비.
  - 10초 단위 시간 버킷(`int(ts) // 10`)으로 분할했으나, 단일 10초 윈도우 내 대량의 정상/비정상 트래픽이 순간 집중될 경우 여전히 단일 버킷이 400KB 상한선에 도달.
* **해결 방법:**
  - **2-버킷 슬라이딩 파티셔닝:** 키 구조를 `WEB#{target}#{source_ip}#{bucket_id}` 모델로 전환하고, 10초 슬라이딩 윈도우 검증 시 직전 버킷($B-1$)과 현재 버킷($B$) 2개만 조회. TTL(30초) 자동 소각 설정.
  - **슬롯 오버플로 청킹(Slot Chunking):** 단일 버킷 내 용량 포화 시 `slot` 인덱스(0..4)를 증분하여 키를 분할(`WEB#{target}#{ip}#{bucket}#{slot}`) 저장. 조회 시 해당 버킷의 모든 활성 슬롯을 병합하여 400KB 제한을 원천 격리.

### 3.5. 비동기 스트림 순서 역전(Out-of-Order) 및 런타임 예외 전파 표준화

* **문제 상황:**
  - **순서 역전:** 네트워크 및 파티션 지연으로 $T_2$ 배치(미래)가 $T_1$ 배치(과거)보다 먼저 인입될 경우, 조회 윈도우가 현재 이벤트 시각 기준 과거 방향으로만 닫혀 있어 지연 도착한 과거 공격 로그가 이미 저장된 미래 로그와 결합되지 못함.
  - **무음 실패(Silent Failure):** DynamoDB 저장/조회 실패를 핸들러 내부에서 `persistence_errors` 리스트에만 담고 정상 응답(`200 OK`)을 리턴하여, Lambda 비동기 재시도 메커니즘 및 DLQ(Dead Letter Queue) 폴백이 완전히 무력화됨.
* **해결 방법:**
  - **양방향 윈도우 평가:** 슬라이딩 윈도우 조회 범위를 현재 시각 기준 과거뿐만 아니라 인접 미래 버킷($B-1, B, B+1$)까지 포괄하는 양방향 조회로 전환하여 순서 역전 인입 시에도 10초 연속 시퀀스 보존.
  - **명시적 예외 전파:** 배치 내 개별 에러 격리는 유지하되, 핸들러 최종 리턴 단계에서 미처리 `PersistenceError` 또는 DB 읽기 장애가 존재할 경우 커스텀 런타임 예외를 상위로 발생(`raise`)시켜 Lambda 서비스 레벨 재시도 및 DLQ 인계를 강제.

### 3.6. 후속 정상 트래픽 혼재 시 지연 공격 이벤트 유효 구간 평가 결함 해결

* **문제 상황:**
  - 후속 정상 트래픽($t=15\text{s}$)이 이미 저장소에 기록된 상태에서 네트워크 버퍼링으로 지연된 공격 로그($t=0\sim 1\text{s}$) 배치가 뒤늦게 인입되는 상황 발생.
  - 당시 `get_active_events` 구현체는 저장된 전체 이벤트 중 단일 최댓값(`anchor_time=15s`)을 찾아 `[anchor_time - 10s, anchor_time]` 구간 밖의 데이터를 일괄 잘라냄(`cutoff = 5s`).
  - 결과적으로 지연 인입된 유효 공격 이벤트($t=0\sim 1\text{s}$)가 필터링 단계에서 영구 삭제되어 시그니처 평가기에 전달되지 못하고 차단이 누락됨.
* **해결 방법:**
  - 단일 전역 앵커 타임 기반의 인위적 10초 자르기 로직을 전면 제거.
  - 현재 평가 대상 요청의 참조 시각(`ref_time`)을 기준으로 유효 영향 구간인 $[T_{ref} - 10\text{s}, T_{ref} + 10\text{s}]$ 양방향 범위의 모든 이벤트를 수집·보존하도록 보정.
  - 실제 10초 시간창 내 임계치 탐지는 전달받은 전체 로그 배열을 대상으로 시그니처 평가기(`evaluate_web_rules`)가 투 포인터(Two-pointer) 알고리즘을 통해 모든 10초 밀집 구간을 완벽하게 전수 탐색하도록 책임을 단일화함.

---

## 4. 핵심 구현 명세 (Technical Specifications)

| 구분 | 설계 명세 | 비고 |
| :--- | :--- | :--- |
| **Partition Key Scheme** | `WEB#{target_identifier}#{source_ip}#{bucket_id}#{slot}` | `bucket_id = int(ts) // 10`, `slot = 0..4` |
| **Read Consistency** | `ConsistentRead=True` (Strongly Consistent Read) | 복제 지연으로 인한 Stale Read 원천 차단 |
| **Data Retention** | `expire_at = (bucket_id + 3) * 10` (DynamoDB TTL) | 30초 후 스토리지 자동 소각 |
| **Sliding Window Range** | $[T_{ref} - 10\text{s}, T_{ref} + 10\text{s}]$ (3개 버킷 양방향 병합) | 지연 도착 및 순서 역전 인입 완벽 대응 |
| **Sliding Algorithm** | Two-Pointer 타임스탬프 슬라이딩 윈도우 | 단일 배치/다중 배치 혼합 시퀀스 전수 평가 |
| **Fault Handling** | 배치 루프 완주 후 미처리 영속화 결함 감지 시 Lambda 함수 예외 전파 | 비동기 재시도 및 DLQ 연계 |

---

## 5. 검증 및 품질 결과 (Verification & Quality Gates)

* **단일 검증 게이트:** `powershell .\scripts\check.ps1` 100% 통과 (Ruff Linter/Formatter 109개 파일 준수).
* **회귀 및 카오스 테스트 슈트:** 683개 Pytest 단위/계약 테스트 전수 통과 (Moto 가상 분산 테스트베드 기반).
  - `test_threat_orchestrator_web_split_batch_independent_runtime_shared_dynamodb`: 독립된 Lambda 런타임 간 3+2 분할 배치 관통 차단 검증.
  - `test_web_attack_window_current_bucket_saturation_overflow_slot_detection`: 단일 버킷 400KB 포화 환경에서 슬롯 오버플로 분할 영속화 및 차단 검증.
  - `test_web_attack_window_out_of_order_batches_detection`: 순서가 뒤집혀 인입된 지연 배치 시퀀스의 양방향 윈도우 병합 및 차단 검증.
  - `test_threat_orchestrator_persistence_failure_raises_function_error`: 저장소 장애 시 무음 실패 방지 및 함수 런타임 예외 발생 검증.
  - `test_web_orchestrator_delayed_batch_with_subsequent_normal_request_detected_and_blocked`: 후속 정상 요청($t=15\text{s}$) 선인입 후 지연 스캔 배치($t=0\sim 1\text{s}$) 인입 시 윈도우 평가 무결성 및 WAF 차단 검증.
  - `test_web_orchestrator_delayed_single_signature_with_normal_request_blocked`: 후속 정상 요청 선인입 후 지연 단일 시그니처($t=0\text{s}$, `/.env`) 인입 시 유효 구간 보존 및 WAF 차단 검증.
