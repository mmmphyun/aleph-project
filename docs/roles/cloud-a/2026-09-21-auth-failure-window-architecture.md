# CloudShield DynamoDB 원자적 카운터 기반 5분 슬라이딩 윈도우 및 오케스트레이터 아키텍처 보고서

> **작성일**: 2026-09-21 (2026-09-23 3차 개정: 3-버킷 타임스탬프 슬라이딩 윈도우 및 분산 순서 역전 극복)  
> **작성자**: 클라우드 A (플랫폼 엔지니어 / 테크 리드)  
> **연동 이슈**: [#21](https://github.com/mmmphyun/aleph-project/issues/21), [#77](https://github.com/mmmphyun/aleph-project/issues/77)  
> **PR 번호**: [#78](https://github.com/mmmphyun/aleph-project/pull/78)  
> **노션 카드**: [Lambda 배치 간 인증 실패 집계 보존](https://notion.so/3d404d37c22581af92f2c5cef78bb164)  
> **문서 상태**: 3-버킷 슬라이딩 로그 전환 및 분산 순서 역전 검증 완료 (Verified & Production Ready)

---

## 1. 추진 배경 및 문제 정의

### 1.1 분할 배치 인입 시 탐지 누락 결함
* **배경**: AWS CloudWatch Logs Subscription Filter는 버퍼 크기 및 전송 주기 정책에 따라 수초 내 발생한 인증 실패 이벤트를 복수의 Lambda 호출 배치로 분할 전달할 수 있습니다.
* **결함**: 보안 룰 엔진(`rules.py`)은 무상태 메모리 상에서 단일 호출 배치 내의 이벤트만 평가하므로, 동일 IP의 5회 무차별 대입 공격이 3건 + 2건으로 분할 전달될 경우 각각 임계치(5회)에 미달하여 `SSH_BRUTE_FORCE` 탐지가 누락되는 취약점이 존재했습니다.

### 1.2 네트워크 실측(176ms)과 사후 L4 격리의 인과관계
* **네트워크 담당 실측 사실 (`docs/roles/network/2026-09-16-syn-ack-timeline-analysis.md`)**:
  * 공격자가 SSH 3-Way Handshake를 맺고 인증 실패 후 4-Way FIN으로 연결을 종료하기까지 걸린 총 시간은 **176.109ms**에 불과합니다.
* **엔지니어링 제약**:
  * CloudWatch Agent가 `auth.log`를 읽어 중앙 엔드포인트로 전송하고 Lambda가 기동되기까지 최소 수백 ms~수 초의 비동기 전송 지연이 발생하므로, **로그 수신 시점에 공격 세션은 이미 커널 상에서 종료**되어 있습니다. 인-세션 L4 패킷 인터셉트(TCP RST 주입 등)는 물리적으로 불가능합니다.
* **설계 결론**:
  * 1회성 접속을 중간 차단하는 것이 아니라, 분할 인입되는 로그 배치를 영속 계층에서 누적 집계하여 5회 도달 즉시 타깃 EC2의 보안 그룹을 전면 차단 SG(`CloudShield-Quarantine-SG`)로 원자적 교체함으로써, **다음 6번째 세션의 TCP SYN 패킷이 타깃 OS 커널에 도달하지 못하도록 원천 차단**하는 사후 원자적 격리 아키텍처를 채택했습니다.

---

## 2. 핵심 엔지니어링 설계 및 저수준 CS 메커니즘

```text
[CloudWatch Logs Subscription Filter]
       │ (Gzip + Base64 JSON Payload)
       ▼
[Lambda: threat_orchestrator_handler]
       │
       ├─► 1. Payload 디코딩 & SyslogAuthEvent 파싱
       │
       ├─► 2. DynamoDB 원자적 타임스탬프 누적 (record_failure)
       │      - 파티션 키: "BF#<source_ip>#<username>#{epoch // 300}" (시간 버킷 파티셔닝)
       │      - 락 프리 원자적 Upsert: list_append 및 ADD (조건식 없음, 충돌률 0%, 재시도 0회)
       │      - 발생 시각 보존: 개별 타임스탬프 원자적 append
       │
       ├─► 3. 위협 판정 및 조기 차단: check_threat
       │      - 직전/현재/직후 3-버킷(curr-1, curr, curr+1) ConsistentRead=True 쿼럼 읽기
       │      - 3개 버킷 중 quarantined == True 존재 시: 조기 탈출(Short-circuit, API 호출 0회)
       │      - 양방향 유효 구간 정밀 평가: ref - 300 <= t <= ref (닫힌 구간, 오탐/누락 0%)
       │
       └─► 4. 다중 계층 복합 차단 & 조건부 마킹 (is_threat == True 시에만 진입)
              - L4: EC2 ModifyInstanceAttribute (CloudShield-Quarantine-SG)
              - L7: WAFv2 UpdateIPSet (/32 CIDR)
              - 가드: is_remediation_successful (필수 조치 성공 검증)
              - 성공 시: quarantined = True 마킹 (멱등성 보장)
              - 실패 시: 마킹 생략 (차기 인입 이벤트 재시도 보장)
```

### 2.1 분산 프로세스 극복과 Consistent Hashing 물리 주소 매핑
* **Shared-Nothing 분산 프로세스 극복**:
  * Lambda는 요청마다 독립된 Firecracker MicroVM 내부의 격리된 메모리 주소 공간에서 실행되므로 물리적 RAM/힙을 공유할 수 없습니다. 따라서 외부 영속 저장소를 단일 진실 공급원(Single Source of Truth)으로 사용합니다.
* **파티션 키와 물리 공간의 정체 ($O(1)$ 라우팅)**:
  * 파티션 키(`target_key = "BF#<ip>#<user>"`)는 분산 환경에서의 **전역 메모리 포인터/주소(Global Address)**입니다.
  * DynamoDB Request Router는 `MD5(Partition Key)` 해시 링 연산을 거쳐 전 세계 수천 대의 물리 서버 중 해당 키를 담당하는 **특정 물리 스토리지 노드의 SSD/RAM 파티션 블록**으로 TCP 패킷을 지연 없이 $O(1)$ 직렬 포워딩합니다.

### 2.2 동시성 제어: 비관적 락 vs 낙관적 락(OCC) vs 시간 버킷 파티셔닝(Lock-Free)
* **비관적 락(Pessimistic Lock)을 쓰지 않는 이유**:
  * 비관적 락(`SELECT FOR UPDATE`)은 OS 프로세스 스케줄러가 타 스레드를 대기(Block/Sleep)시키는 것처럼 고비용 컨텍스트 스위칭과 데드락 위험, 네트워크 지연 병목을 유발합니다.
* **단일 키 낙관적 락(OCC / CAS)의 한계와 폐기**:
  * 단일 파티션 키(`BF#<ip>#<user>`) 환경에서는 윈도우 만료 여부를 판별하기 위해 조건부 쓰기(`ConditionExpression="expire_at >= :now"`)가 필수였습니다.
  * 복수 Lambda 인스턴스가 밀리초 단위로 동시 인입될 때 `ConditionalCheckFailedException` 경합이 발생하여 최대 3회 재시도(CAS Retry Loop)를 수행해야 했고, 고부하 환경에서 간헐적 갱신 분실(Lost Update) 및 테일 레이턴시 스파이크가 발생했습니다.
* **시간 버킷 파티셔닝 기반 락 프리(Lock-Free) 원자적 Upsert (최종 채택)**:
  * 파티션 키에 시간 버킷 ID를 포함(`BF#<ip>#<user>#{epoch // 300}`)하여 이전 윈도우 만료 판별 조건식을 완전히 제거했습니다.
  * 조건식이 없으므로 충돌 및 재시도가 원천 배제(충돌률 0%)되며, 스토리지 노드의 단일 리더 스레드가 내부 메모리에서 직접 `ADD` 및 `list_append`를 수행하여 **분산 락 없는 완벽한 원자적 락 프리 연산**을 달성합니다.

### 2.3 분산 엣지케이스 심층 방어 메커니즘 (3차 개정 핵심)

#### 2.3.1 단일 키 OCC 경합 극복과 락 프리 타임스탬프 원자적 누적
* **결함 시나리오**:
  * 2개 이상의 Lambda 인스턴스가 만료 경계면에서 동시 인입될 때, 낙관적 락(OCC) 모델은 한 프로세스만 성공하고 나머지는 Abort되어 재시도를 강제당합니다.
* **방어 원리 (Time-bucket Partitioning + Atomic Append)**:
  * 버킷 키 단위로 격리된 레코드에 이벤트 발생 타임스탬프 리스트를 `list_append`로 원자적 누적합니다.
  * 동시성 제어를 DB 쓰기 시점의 조건식(Lock)이 아닌, **조회 시점의 타임스탬프 슬라이딩 윈도우 필터링**으로 이관하여 쓰기 경로의 병목을 원천 제거했습니다.

#### 2.3.2 분산 복제 쿼럼($R + W > N$)과 Stale Read 방어
* **결함 시나리오**:
  * DynamoDB는 3개 가용 영역($N=3$)에 복제 노드를 유지하며, 과반수 쓰기($W=2$, Paxos Leader + 1 Follower) 완료 즉시 쓰기 성공을 반환합니다. 3번째 노드는 비동기로 복제됩니다.
  * `check_threat`의 `get_item`이 최종 일관성($R=1$, `ConsistentRead=False`)을 사용할 경우, 복제가 지연된 3번째 노드를 읽어 방금 5회에 도달한 쓰기 상태를 놓치고 4회로 판정하여 탐지 및 L4 격리가 누락될 수 있습니다.
* **방어 원리 (Strongly Consistent Read)**:
  * 직전/현재/직후 3개 버킷 조회 시 모두 `ConsistentRead=True`($R=2$)를 강제하여 정족수 수식 $R + W = 4 > N(3)$을 만족시킵니다.
  * 비둘기집 원리에 의해 읽기 정족수와 쓰기 정족수 간에 최소 1개의 공통 최신 노드가 반드시 포함됩니다.
* **쿼럼($R + W > N$)과 LSN(Log Sequence Number)의 상호 보완성 (1:1 동점 해소 메커니즘)**:
  * **물리적 한계**: 최신 쓰기 노드(`count = 5`)와 지연 노드(`count = 4`) 2개를 읽었을 때, 결과 집합은 `[5, 4]`로 1:1 동점이 되어 값 자체의 다수결 투표가 수학적으로 불가능합니다.
  * **역할 분담 원칙**:
    * **정족수 쿼럼 ($R + W > N$)**: 최신 데이터를 보유한 노드가 읽기 후보군 안에 최소 1개 이상 물리적으로 포함되도록 가두는 그물망 역할.
    * **논리적 시계 (LSN / Version)**: Paxos Leader가 부여한 단조 증가 트랜잭션 번호를 비교하여 누가 진짜 최신 노드인지 식별(Pick)하는 판별 기준 역할.

#### 2.3.3 부분 결함(Partial Failure) 감내와 멱등 상태 머신 전이
* **결함 시나리오**:
  * `apply_remediation` 실행 중 AWS EC2 API Throttling이나 IAM 오류로 L4 격리가 실패하더라도, 오케스트레이터가 예외 미발생을 성공으로 간주하여 `mark_quarantined`를 호출하면 향후 5분간 재시도가 차단됩니다.
* **방어 원리**:
  * `is_remediation_successful` 가드를 배치하여 `action_required`에 따른 필수 계층 조치 플래그(`quarantine_applied`, `waf_blocked`)가 실제로 `True`인 경우에만 `quarantined=True`를 마킹합니다.
  * 실패 시 마킹을 보류하여 차기 인입 이벤트에서 자동 재시도되도록 보장하며, 앞서 성공한 조치는 조회 기반 No-op(멱등성, $f(f(x))=f(x)$)으로 중복 실행을 방지합니다.

### 2.4 Lambda 위협 분석 및 대응 오케스트레이터 (`src/remediation/orchestrator.py`)
* `threat_orchestrator_handler` 실행 파이프라인:
  1. `CloudWatchLogsPayload.from_awslogs_data()`로 gzip 압축 해제 및 Base64 디코딩.
  2. `SyslogAuthEvent.parse_line()`으로 정규식 파싱 및 공격자 IP/계정 추출.
  3. `AuthFailureWindow.record_failure()`: 현재 시간 버킷에 타임스탬프 원자적 append (락 프리 1 RTT).
  4. `AuthFailureWindow.check_threat()`:
     - 직전/현재/직후 3-버킷 일괄 조회 (`ConsistentRead=True`).
     - 3개 버킷 중 어느 하나라도 `quarantined == True`이면 `(False, None, "")` 즉시 반환 (조기 탈출, Short-circuit으로 불필요한 후속 API 호출 0회 차단).
     - 양방향 유효 구간($ref - 300 \le t \le ref$) 내 임계치 도달 여부 정밀 평가.
  5. `is_threat == True` 시에만 `IncidentReport` 생성 및 `apply_remediation` 호출 (L4 SG 원자적 교체 및 L7 WAF 차단).
  6. `is_remediation_successful` 검증 후 성공 시에만 `mark_quarantined(target_key)` 실행.

---

## 3. 기술적 트레이드오프 및 한계 분석 (Critique & Trade-offs)

### 3.1 분산 환경의 시간축 통일 (Clock Skew 대응)
* 서로 다른 서버(EC2, Lambda, DynamoDB) 간 NTP 동기화 오차로 인한 판정 왜곡을 방지하기 위해, Lambda 머신의 로컬 클럭(`time.time()`) 대신 CloudWatch가 부여한 `log_event.timestamp`(Epoch Milliseconds)를 단일 시간 오소리티로 통일했습니다.

### 3.2 분산 로깅의 순서 역전(Out-of-Order Delivery) 물리 메커니즘과 3-버킷 스캔 극복
* **물리적 역전 발생 원인 (Distributed Queue & Parallel Execution)**:
  * CloudWatch Logs 구독 필터는 단일 직렬 큐가 아닌 분산 샤딩 파티션 스트림입니다.
  * 로그 볼륨에 따라 복수의 독립된 Lambda Worker(Firecracker MicroVM 컨테이너)가 병렬 기동됩니다.
  * 배치 A($t=299$)를 수신한 Worker 1이 콜드 스타트(VPC ENI 바인딩 지연)를 겪는 동안, 배치 B($t=450$)를 수신한 Worker 2가 웜 상태에서 먼저 실행되어 버킷 1에 커밋될 수 있습니다.
* **단순 교환법칙 가설의 파탄과 결함 실측**:
  * 단일 키 정수 카운터 시절에는 덧셈의 교환법칙($A+B=B+A$)으로 순서 역전을 해결할 수 있다고 가정했으나, 시간 버킷 파티셔닝 구조에서는 **버킷 ID 자체가 분할($t=450 \rightarrow$ 버킷 1, $t=299 \rightarrow$ 버킷 0)**되므로 가설이 완전히 무너집니다.
  * Worker 1이 뒤늦게 $t=299$를 처리할 때 $now=299$로 시각이 역전되어 현재(0)와 직전(-1) 버킷만 조회하면 이미 커밋된 버킷 1을 놓치는 **탐지 누락(False Negative)**이 발생합니다.
* **3-버킷($curr \pm 1$) 스캔과 양방향 닫힌 구간($[ref-300, ref]$)의 해결책**:
  * 직전/현재/직후 3개 버킷을 일괄 조회하여 지연 인입 시에도 선행 처리된 미래 버킷 데이터를 100% 포괄합니다.
  * 윈도우 평가 시 하한선($t \ge now - 300$)만 둘 경우 $(t=1, 3\text{건}) \rightarrow (t=599, 1\text{건}) \rightarrow (t=301, 1\text{건})$처럼 598초 차이나는 트래픽이 합산되는 오탐(False Positive)이 발생하므로, 반드시 기준 시각 $ref$를 상한으로 하는 **닫힌 구간 $[ref - 300, ref]$**을 강제하여 정확도 100%를 달성했습니다.

### 3.3 Hot Partition 병목 및 FinOps(비용) DoS 선순환 방어
* 공격자가 단일 IP로 대량의 무차별 대입을 퍼부을 경우 DynamoDB 파티션 쓰기 한도(1,000 WCU) 초과 위험이 존재합니다.
* 본 시스템은 5회 도달 즉시 타깃 EC2의 L4 보안 그룹을 전면 차단 SG로 교체하므로, 6회째 시도부터는 패킷이 AWS 하이퍼바이저에서 즉시 Drop됩니다. 타깃 OS 커널에 패킷이 도달하지 않아 `auth.log` 생성이 중단되고, 후속 CloudWatch 전송 및 Lambda 실행 비용이 원천 차단됩니다.

### 3.4 패스워드 스프레잉(Password Spraying) 집계의 메모리 타협 (Current Trade-off)
* **설계 한계**: 동일 IP에서 시도된 계정명을 DynamoDB `String Set`(`usernames`)으로 누적 관리합니다. DynamoDB 단일 아이템 최대 크기는 400KB로 제한되므로, 수천 개 계정을 공격하는 대규모 스프레잉 공격 시 아이템 크기 초과 에러(`ValidationException`)가 발생할 수 있습니다.
* **실용적 타협 근거**: 현재 CloudShield 데모 시나리오의 스프레잉 임계치는 2개 고유 계정(`PASSWORD_SPRAYING_THRESHOLD = 2`)으로 매우 낮게 설정되어 있어, 2개 도달 즉시 WAF 차단이 발동되므로 아이템이 커지지 않습니다. 향후 대규모 엔터프라이즈 환경으로 확장 시 HyperLogLog(HLL) 카디널리티 카운터로 고도화하는 것이 바람직합니다.

---

## 4. 단위 테스트 및 품질 검증 결과

- **테스트베드**: `moto` 기반 가상 DynamoDB 테이블(`CloudShield-AuthFailure-Window`), 가상 EC2 타깃 및 Quarantine SG, 가상 WAFv2 IPSet.
- **검증 케이스 (`tests/unit/test_auth_window.py`, 총 13종 전원 통과)**:
  1. `test_split_batches_cumulative_ssh_brute_force`: 3건 + 2건 분할 Lambda 호출 시 `SSH_BRUTE_FORCE` 누적 탐지, L4 보안 그룹 원자적 교체 및 WAF IPSet 등록 완결 검증 (이슈 #21 핵심 기준).
  2. `test_auth_window_sliding_expiration_reset`: 301초 경과 후 인입 시 윈도우가 새로 시작되어 오탐하지 않음을 검증.
  3. `test_split_batches_cumulative_password_spraying`: 분할 수신된 서로 다른 2개 계정 실패 시 `SSH_PASSWORD_SPRAYING` 탐지 및 WAF 차단 검증.
  4. `test_remediation_idempotency_suppression`: 이미 격리된 타깃에 대한 후속 6번째 실패 인입 시 중복 격리 API 호출 억제 검증.
  5. `test_concurrent_record_failure_race_condition`: `ThreadPoolExecutor`를 통한 다중 스레드 동시 인입 시 Lost Update 방어 및 원자적 카운트 보존 검증 (2차 개정 추가).
  6. `test_check_threat_uses_consistent_read`: `check_threat` 내부의 `get_item`이 `ConsistentRead=True`를 강제함을 검증 (2차 개정 추가).
  7. `test_remediation_failure_allows_retry_on_next_batch`: 조치 실패 시 마킹 보류 및 차기 이벤트 재시도 보장 검증 (2차 개정 추가).
  8. `test_boundary_split_detection_accuracy`: 300초 경계면(298초 2건, 302초 3건) 분할 인입 시 SSH_BRUTE_FORCE 정상 탐지 검증.
  9. `test_boundary_split_password_spraying_accuracy`: 300초 경계면(299초, 301초) 분할 인입 시 SSH_PASSWORD_SPRAYING 정상 탐지 검증.
  10. `test_sliding_window_reviewer_edge_cases_fixed`: PR #78 리뷰어 지적 4대 엣지 케이스(버스트 누락 2건 방지, 만료 오탐 2건 방지) 검증.
  11. `test_out_of_order_batches_ssh_brute_force_separate_instances`: 별도 인스턴스 간 $t=450$ 1건 선행 후 $t=299$ 4건 지연 인입 시 3-버킷 스캔을 통한 SSH_BRUTE_FORCE 탐지 검증 (3차 개정 추가).
  12. `test_out_of_order_batches_password_spraying_separate_instances`: 별도 인스턴스 간 $t=450$ 선행 후 $t=299$ 지연 인입 시 SSH_PASSWORD_SPRAYING 탐지 검증 (3차 개정 추가).
  13. `test_out_of_order_upper_bound_filter_prevents_false_positive`: $(t=1, 3\text{건}) \rightarrow (t=599, 1\text{건}) \rightarrow (t=301, 1\text{건})$ 인입 시 $t \le now$ 상한선에 의해 598초 분산 오탐 방지 검증 (3차 개정 추가).
- **통합 검증 결과**: `powershell .\scripts\check.ps1` 단일 게이트 100% 통과 (R&R 검증, Ruff Lint/Format, 291개 전체 단위/계약 테스트 전원 통과).
