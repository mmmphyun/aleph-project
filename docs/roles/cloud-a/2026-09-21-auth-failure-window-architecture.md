# CloudShield DynamoDB 원자적 카운터 기반 5분 슬라이딩 윈도우 및 오케스트레이터 아키텍처 보고서

> **작성일**: 2026-09-21  
> **작성자**: 클라우드 A (플랫폼 엔지니어 / 테크 리드)  
> **연동 이슈**: [#21](https://github.com/mmmphyun/aleph-project/issues/21)  
> **노션 카드**: [Lambda 배치 간 인증 실패 집계 보존](https://notion.so/3d404d37c22581af92f2c5cef78bb164)  
> **문서 상태**: 검증 완료 (Verified)

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
       ├─► 2. DynamoDB 원자적 카운터 누적 (AuthFailureWindow)
       │      - 파티션 키: "BF#<source_ip>#<username>" (Global Address)
       │      - 해시 링 라우팅: MD5(PK) -> 특정 스토리지 노드 파티션 블록 O(1) 매핑
       │      - Condition: attribute_exists(...) AND expire_at >= :now
       │      - True  ──► ADD failure_count :inc (Lock-Free Storage Serialized)
       │      - False ──► SET failure_count = :inc, expire_at = :now + 300 (CAS Reset)
       │
       ├─► 3. 위협 판정: failure_count >= 5 AND quarantined == False
       │
       └─► 4. 다중 계층 복합 차단 (apply_remediation)
              - L4: EC2 ModifyInstanceAttribute (CloudShield-Quarantine-SG)
              - L7: WAFv2 UpdateIPSet (/32 CIDR)
              - State: DynamoDB quarantined = True 마킹 (멱등성 보장)
```

### 2.1 분산 프로세스 극복과 Consistent Hashing 물리 주소 매핑
* **Shared-Nothing 분산 프로세스 극복**:
  * Lambda는 요청마다 독립된 Firecracker MicroVM 내부의 격리된 메모리 주소 공간에서 실행되므로 물리적 RAM/힙을 공유할 수 없습니다. 따라서 외부 영속 저장소를 단일 진실 공급원(Single Source of Truth)으로 사용합니다.
* **파티션 키와 물리 공간의 정체 ($O(1)$ 라우팅)**:
  * 파티션 키(`target_key = "BF#<ip>#<user>"`)는 분산 환경에서의 **전역 메모리 포인터/주소(Global Address)**입니다.
  * DynamoDB Request Router는 `MD5(Partition Key)` 해시 링 연산을 거쳐 전 세계 수천 대의 물리 서버 중 해당 키를 담당하는 **특정 물리 스토리지 노드의 SSD/RAM 파티션 블록**으로 TCP 패킷을 지연 없이 $O(1)$ 직렬 포워딩합니다.

### 2.2 동시성 제어: 비관적 락 vs 하드웨어 레벨 원자적 연산 vs 조건부 쓰기(CAS)
* **비관적 락(Pessimistic Lock)을 쓰지 않는 이유**:
  * 비관적 락(`SELECT FOR UPDATE`)은 OS 프로세스 스케줄러가 타 스레드를 대기(Block/Sleep)시키는 것처럼 고비용 컨텍스트 스위칭과 데드락 위험, 네트워크 지연 병목을 유발합니다.
* **원자적 카운터(`ADD failure_count :inc`)의 동작 원리**:
  * 클라이언트가 값을 읽어와 연산하는 R-M-W(Read-Modify-Write) 방식이 아닙니다.
  * 스토리지 노드의 단일 리더 스레드가 내부 메모리에서 직접 숫자를 1단위로 증가시키고 WAL에 순차 기록합니다. 이는 CPU 어셈블리의 `LOCK XADD` 명령어처럼 **분산 락 없는(Lock-Free) 단일 직렬화**로 완벽한 원자성을 보장합니다.
* **조건부 쓰기(`expire_at >= :now`)와 Compare-And-Swap(CAS)**:
  * DynamoDB의 내장 TTL은 백그라운드 청소 스레드가 비동기로 수집하므로 최대 48시간 지연 삭제될 수 있습니다. 300초 정각 하드웨어 삭제에 의존하면 심각한 오탐이 발생합니다.
  * 따라서 애플리케이션 레벨에서 **낙관적 동시성 제어(OCC) 기반 Compare-And-Swap(CAS)**을 적용했습니다.
  * 스토리지 노드가 쓰기 직전 `expire_at >= :now`를 비교하여, 만료 시 작업을 즉시 Abort하고 `ConditionalCheckFailedException`을 반환합니다. 클라이언트는 이를 포착하여 `SET failure_count = 1, expire_at = now + 300`으로 윈도우를 강제 리셋합니다.

### 2.3 Lambda 위협 분석 및 대응 오케스트레이터 (`src/remediation/orchestrator.py`)
* `threat_orchestrator_handler`:
  1. `CloudWatchLogsPayload.from_awslogs_data()`로 gzip 압축 해제 및 Base64 디코딩.
  2. `SyslogAuthEvent.parse_line()`으로 정규식 파싱 및 공격자 IP/계정 추출.
  3. `AuthFailureWindow`에 인증 실패를 원자적으로 누적.
  4. 5회 이상 누적 시 `IncidentReport` 자동 생성 (`mitre_id="T1110.001"`, `action_required="BLOCK_AND_QUARANTINE"`).
  5. `apply_remediation` 호출로 L4 EC2 보안 그룹 교체 및 L7 WAF 차단 수행.
  6. 차단 완료 시 `quarantined=True` 플래그를 설정하여 동일 윈도우 내 후속 실패로 인한 중복 차단 API 호출 억제(Idempotency).

---

## 3. 기술적 트레이드오프 및 한계 분석 (Critique & Trade-offs)

### 3.1 분산 환경의 시간축 통일 (Clock Skew 대응)
* 서로 다른 서버(EC2, Lambda, DynamoDB) 간 NTP 동기화 오차로 인한 판정 왜곡을 방지하기 위해, Lambda 머신의 로컬 클럭(`time.time()`) 대신 CloudWatch가 부여한 `log_event.timestamp`(Epoch Milliseconds)를 단일 시간 오소리티로 통일했습니다.

### 3.2 분산 로깅의 순서 역전(Out-of-Order Delivery) 대응
* CloudWatch Logs는 엄격한 In-Order Delivery를 보장하지 않습니다.
* 덧셈 연산(`ADD failure_count :inc`)은 교환법칙($A + B = B + A$)이 성립하므로, 3건 배치와 2건 배치의 인입 순서가 뒤바뀌더라도 최종 합산 결과는 항상 5로 일정하게 유지됩니다.

### 3.3 Hot Partition 병목 및 FinOps(비용) DoS 선순환 방어
* 공격자가 단일 IP로 대량의 무차별 대입을 퍼부을 경우 DynamoDB 파티션 쓰기 한도(1,000 WCU) 초과 위험이 존재합니다.
* 본 시스템은 5회 도달 즉시 타깃 EC2의 L4 보안 그룹을 전면 차단 SG로 교체하므로, 6회째 시도부터는 패킷이 AWS 하이퍼바이저에서 즉시 Drop됩니다. 타깃 OS 커널에 패킷이 도달하지 않아 `auth.log` 생성이 중단되고, 후속 CloudWatch 전송 및 Lambda 실행 비용이 원천 차단됩니다.

### 3.4 패스워드 스프레잉(Password Spraying) 집계의 메모리 타협 (Current Trade-off)
* **설계 한계**: 동일 IP에서 시도된 계정명을 DynamoDB `String Set`(`usernames`)으로 누적 관리합니다. DynamoDB 단일 아이템 최대 크기는 400KB로 제한되므로, 수천 개 계정을 공격하는 대규모 스프레잉 공격 시 아이템 크기 초과 에러(`ValidationException`)가 발생할 수 있습니다.
* **실용적 타협 근거**: 현재 CloudShield 데모 시나리오의 스프레잉 임계치는 2개 고유 계정(`PASSWORD_SPRAYING_THRESHOLD = 2`)으로 매우 낮게 설정되어 있어, 2개 도달 즉시 WAF 차단이 발동되므로 아이템이 커지지 않습니다. 향후 대규모 엔터프라이즈 환경으로 확장 시 HyperLogLog(HLL) 카디널리티 카운터로 고도화하는 것이 바람직합니다.

---

## 4. 단위 테스트 및 품질 검증 결과

- **테스트베드**: `moto` 기반 가상 DynamoDB 테이블(`CloudShield-AuthFailure-Window`), 가상 EC2 타깃 및 Quarantine SG, 가상 WAFv2 IPSet.
- **검증 케이스 (`tests/unit/test_auth_window.py`)**:
  1. `test_split_batches_cumulative_ssh_brute_force`: 3건 + 2건 분할 Lambda 호출 시 `SSH_BRUTE_FORCE` 누적 탐지, L4 보안 그룹 원자적 교체 및 WAF IPSet 등록 완결 검증 (이슈 #21 핵심 기준).
  2. `test_auth_window_sliding_expiration_reset`: 301초 경과 후 인입 시 윈도우가 1로 리셋되어 오탐하지 않음을 검증.
  3. `test_split_batches_cumulative_password_spraying`: 분할 수신된 서로 다른 2개 계정 실패 시 `SSH_PASSWORD_SPRAYING` 탐지 및 WAF 차단 검증.
  4. `test_remediation_idempotency_suppression`: 이미 격리된 타깃에 대한 후속 6번째 실패 인입 시 중복 격리 API 호출 억제 검증.
- **통합 검증 결과**: `powershell .\scripts\check.ps1` 단일 게이트 100% 통과 (R&R 검증, Ruff Lint/Format, 235개 단위/계약 테스트 전원 통과).
