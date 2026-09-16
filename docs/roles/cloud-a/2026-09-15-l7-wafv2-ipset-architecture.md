# CloudShield Boto3 기반 L7 AWS WAFv2 IPSet /32 원자적 차단 아키텍처 및 검증 보고서

> **작성일**: 2026-09-15  
> **작성자**: 클라우드 A (플랫폼 엔지니어 / 테크 리드)  
> **연동 이슈**: [#50](https://github.com/mmmphyun/aleph-project/issues/50)  
> **문서 상태**: 검증 완료 (Verified)

---

## 1. 추진 배경 및 목적

- **문제 정의**:
  - 웹 애플리케이션 및 API 대상의 L7 침해 공격(Credential Stuffing, HTTP Spraying, 웹 취약점 스캐닝 등) 발생 시, 서비스 전체를 중단시키지 않고 악성 요청을 유발하는 공격자의 출발지 IP만을 엣지(Edge/Regional) 레벨에서 즉각 차단해야 함.
  - 단순 IP 추가 방식은 동시성 충돌(Race Condition)에 취약하여 다수의 Lambda 인스턴스가 동시에 WAF IPSet을 갱신할 경우 선행 차단 IP가 유실(Lost Update)되거나 트랜잭션이 실패할 위험이 존재함.
- **목적**:
  - `IncidentReport`의 지시어(`BLOCK_WAF`, `BLOCK_AND_QUARANTINE`, `BLOCK_IP_ONLY`) 수신 즉시 AWS WAFv2 Regional IPSet에 공격자 IP를 `/32` CIDR 규격으로 원자적 등록.
  - WAFv2 `LockToken` 기반 낙관적 동시성 제어(Optimistic Locking)와 상태 기반 멱등성을 적용하여 무결성과 가용성을 동시에 확보.

---

## 2. 핵심 엔지니어링 설계 및 구현

### 2.1 낙관적 동시성 제어 (Optimistic Locking via `LockToken`)
- **API 채택**: `wafv2.update_ip_set(Name=..., Scope=..., Id=..., Addresses=..., LockToken=...)`
- **설계 근거 및 동작 원리**:
  - AWS WAFv2는 리소스 수정 시 분산 락을 제공하지 않는 대신, 읽기 시점의 토큰(`LockToken`)을 수정 시점에 대조하는 **낙관적 동시성 제어**를 강제함.
  - `get_ip_set`을 통해 현재 `LockToken`과 `Addresses`를 취득한 뒤, 원자적 병합을 거쳐 `update_ip_set`을 호출함.
  - 다중 Lambda 실행으로 인해 중간에 다른 프로세스가 IPSet을 갱신한 경우 `WAFOptimisticLockException`이 발생하며, 엔진은 이를 포착하여 최신 상태를 재조회한 뒤 최대 3회(`MAX_WAF_UPDATE_RETRIES`)까지 자동 재시도(Retry Loop)를 수행함.

### 2.2 폭발 반경(Blast Radius) 방지를 위한 엄격한 `/32` CIDR 강제
- **설계 근거**:
  - 서브넷 마스크 없이 IP 주소만 전달되는 경우 파이썬 표준 라이브러리 `ipaddress`를 통해 유효성을 검증하고 단일 호스트 표기법인 `/32`로 자동 보정함.
  - 만약 `/24` 등 광범위한 서브넷 대역이 인입될 경우, 동일 ISP 또는 클라우드 대역을 공유하는 수백 명의 정상 사용자가 일괄 차단되는 오차단(Blast Radius 확산) 사고가 발생할 수 있으므로, 엔진 레벨에서 prefixlen이 32가 아닌 요청은 작업을 즉시 거부(`False`)하도록 통제함.

### 2.3 상태 기반 멱등성 (Idempotency) 및 비용 최적화
- **사전 상태 검사**:
  - 대상 IP(/32)가 이미 WAF IPSet의 `Addresses` 목록에 존재하는 경우, WAFv2 `update_ip_set` API 호출을 생략하고 즉시 `True`를 반환함.
  - 불필요한 AWS WAF 쓰기 API 호출 비용(WAF API 요청 과금)을 절감하고, 불필요한 `LockToken` 갱신으로 인한 타 프로세스와의 경합을 사전에 방지함.
- **주소 목록 무결성 보장**:
  - 신규 주소 병합 시 `dict.fromkeys([*current_addresses, target_cidr])`를 적용하여 기존 차단 순서를 보존하면서 중복 주소 유입을 원천 차단함.

### 2.4 결함 격리 (Fault Isolation)
- WAFv2 API 호출 중 발생하는 `ClientError`(권한 부족, IPSet 부재, 한도 초과 등)는 내부에서 로깅 후 `waf_blocked: False`로 반환함.
- 상위 오케스트레이터(`apply_remediation`)에서 L4 격리(`quarantine_applied`) 및 이후 Slack 상황 전파 파이프라인이 중단되지 않도록 계층 간 장애 전파를 철저히 차단함.

---

## 3. 기술 검증 및 트레이드오프 분석 (Technical Critique & Q&A)

### 3.1 분산 락(Redis/DynamoDB) 대신 WAFv2 네이티브 LockToken을 채택한 이유
- **질문/쟁점**: 동시성 충돌을 원천 차단하기 위해 Lambda 앞단에 DynamoDB나 Redis 분산 락을 두는 것이 더 안전하지 않은가?
- **트레이드오프 분석**:
  - **운영 오버헤드 및 지연 시간**: 분산 락 인프라(DynamoDB Lock, ElastiCache Redis)를 도입하면 배포 복잡도, 유지보수 비용, 추가적인 네트워크 왕복 지연(RTT)이 발생하여 10초 관통 대응 목표에 불리함.
  - **AWS WAFv2 자체 제공 메커니즘**: AWS WAFv2는 이미 완벽한 낙관적 락(`LockToken`)을 네이티브 지원하므로, 애플리케이션 레벨에서 가벼운 재시도 루프(Max 3회)를 결합하는 것만으로 외부 인프라 의존성 없이 100% 원자적 일관성을 달성할 수 있음.

### 3.2 WAF IPSet 용량 한도(Capacity Limits) 및 대규모 침해 시의 대응 전략
- **질문/쟁점**: WAF IPSet에 등록 가능한 IP 수 한도(기본 10,000개)가 초과되거나 대규모 DDoS 공격이 발생할 경우의 한계는?
- **계층별 보안 대응 체계**:
  - **L7 WAF IPSet**: 단일 공격자, 소규모 웹 브루트포스 및 스캐닝을 정밀 차단하는 핀포인트 방어선.
  - **한도 초과 시 조치**: WAF IPSet 한도 도달 시 `WAFLimitsExceededException`이 발생할 수 있으며, 실제 엔터프라이즈 환경에서는 오래된 차단 IP를 자동 해제하는 TTL 기반 슬라이딩 윈도우 큐 또는 CloudWatch 경보 기반의 IPSet 분할 관리가 수반되어야 함.
  - **대규모 볼류메트릭 DDoS**: L7 WAF IP 차단이 아닌 AWS Shield Advanced 및 CloudFront 엣지 차단, L4 Network ACL로 대응 레벨을 상향 이관해야 함.

### 3.3 낙관적 락(Optimistic Lock) vs 비관적 락(Pessimistic Lock) 엔지니어링 분석

#### (1) 낙관적 락 4단계 동작 라이프사이클
```text
1. 읽기 (Read)        : WAF IPSet 데이터와 함께 현재 버전(LockToken="v1")을 조회 (락을 잡지 않음).
2. 로컬 가공 (Compute) : 메모리에서 공격자 IP를 기존 목록에 추가 (타 Lambda 프로세스도 동시 읽기/가공 허용).
3. 커밋 시도 (Commit)  : update_ip_set(Addresses=..., LockToken="v1") 호출.
4. 서버 검증 (Validate) :
   - WAF 서버의 현재 토큰이 "v1"이면 -> 저장 성공 및 LockToken 자동 갱신("v2").
   - 타 프로세스가 먼저 갱신하여 현재 토큰이 "v2"이면 -> 'WAFOptimisticLockException' 거부.
5. 재시도 루프 (Retry)  : 충돌 시 작업을 폐기하지 않고, 1번(Read)부터 재수행하여 최신 토큰("v2")과 최신 목록을 Re-fetch 후 재병합.
```

#### (2) 비관적 락 vs 낙관적 락 비교 매트릭스
| 비교 항목 | 비관적 락 (Pessimistic Lock) | 낙관적 락 (Optimistic Lock) |
| :--- | :--- | :--- |
| **기본 철학** | "충돌이 무조건 발생할 것이다" (사전 잠금) | "충돌이 드물게 발생할 것이다" (사후 검증) |
| **동작 방식** | `SELECT FOR UPDATE` 등으로 데이터에 락을 걸고 타 프로세스 대기(Blocking) | 락 없이 자유롭게 읽기/가공 수행, 커밋 시점에 버전(`LockToken`) 대조 |
| **장점** | - 데이터 충돌 원천 차단<br>- 재시도 로직 불필요 (1회 트랜잭션 완결) | - **블로킹이 없어 대기 시간(Latency) 최소화**<br>- **데드락(Deadlock) 위험 전무**<br>- 외부 분산 락(Redis/DB) **인프라 비용 제로** |
| **단점** | - 대기 지연으로 인한 **전체 시스템 처리량(Throughput) 저하**<br>- 락 미해제 시 **데드락** 위험 | - **충돌 빈발 시 재시도(Retry) 폭증**으로 네트워크/CPU 부하 가중<br>- 최대 재시도 초과 시 실패 가능성 존재 |
| **관리 주체** | 중앙 집중식 락 매니저 (Redis Redlock, DynamoDB Lock Table) | AWS WAFv2 서버 토큰 검증 + 애플리케이션 재시도 루프 |

#### (3) CloudShield 차단 엔진 채택 근거 및 역선택 기준
- **낙관적 락 채택 근거 (Why)**:
  1. **낮은 충돌 빈도 (Low Contention)**: 단일 IPSet에 초당 수천 건의 차단이 동시 인입되지 않는 한, 대부분의 Lambda는 1회차에 무경합 성공함.
  2. **무상태(Stateless) 서버리스 환경**: Lambda 런타임 간 상태 공유가 불가능하여 비관적 락을 쓰려면 중앙 락 저장소를 별도 운영해야 하는 과도한 엔지니어링(Over-engineering) 방지.
  3. **10초 관통 대응 SLA**: 타 프로세스의 락 해제를 대기(Wait)하지 않고 즉시 가공에 착수하여 응답 지연을 원천 제거.
- **비관적 락 / FIFO 대기열 큐가 필요한 환경 (역선택 기준)**:
  - 수강신청, 한정 수량 선착순 티켓팅, 은행 계좌 잔액 차감 등 동일 자원에 대해 수천 개의 트랜잭션이 동시 쓰기를 경쟁하는 **High Contention** 도메인. 이러한 도메인에 낙관적 락을 적용할 경우 대다수 트랜잭션이 충돌 실패하여 재시도 폭풍(Thundering Herd)으로 시스템이 마비되므로 비관적 락이나 직렬화 큐가 강제됨.

---

## 4. 단위 테스트 및 품질 검증 결과

- **테스트베드**: `moto` 기반 가상 AWS WAFv2 Regional 환경.
- **검증 항목**:
  1. `test_find_waf_ip_set_success`: 명칭 기반 IPSet 메타데이터(Id, Name, ARN) 동적 조회 성공.
  2. `test_find_waf_ip_set_not_found`: 미존재 IPSet에 대한 안전한 None 반환.
  3. `test_block_ip_wafv2_success`: 단일 IPv4 입력 시 `/32` CIDR로 정상 추가 및 WAF 조회 일치.
  4. `test_block_ip_wafv2_idempotent`: 동일 IP 2회 연속 호출 시 중복 생성 없이 멱등 성공 보장.
  5. `test_block_ip_wafv2_invalid_ip`: 비정상 IP 형식 거부 및 결함 격리.
  6. `test_block_ip_wafv2_non_32_prefix_rejected`: `/24` 광범위 대역 거부로 오차단 방지.
  7. `test_block_ip_wafv2_not_found_ipset`: IPSet 미존재 시 False 반환.
  8. `test_block_ip_wafv2_optimistic_lock_retry`: `WAFOptimisticLockException` 발생 시 자동 재시도 및 성공 검증.
  9. `test_apply_remediation_waf_action_routing`: `BLOCK_WAF`, `BLOCK_IP_ONLY` 액션 라우팅 검증.
  10. `test_atomic_remediation_success`: L4 SG 격리 + L7 WAF 차단 동시 완결 통합 검증 (스킵 해제 완료).
