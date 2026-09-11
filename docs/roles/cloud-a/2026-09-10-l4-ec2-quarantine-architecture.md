# CloudShield Boto3 기반 L4 EC2 Quarantine SG 원자적 격리 아키텍처 및 검증 보고서

> **작성일**: 2026-09-10  
> **작성자**: 클라우드 A (플랫폼 엔지니어 / 테크 리드)  
> **연동 이슈**: [#31](https://github.com/mmmphyun/aleph-project/issues/31)  
> **문서 상태**: 검증 완료 (Verified)

---

## 1. 추진 배경 및 목적

- **문제 정의**:
  - 침해 사고(SSH 무차별 대입, 원격 명령 실행 등) 발생 시 침해 호스트를 방치하면 내부 VPC 내 타 인스턴스/데이터베이스로의 횡적이동(Lateral Movement) 및 공격자 C2(Command & Control) 서버와의 데이터 유출이 급속히 전개됨.
  - 기존의 보안 그룹 룰 개별 삭제 방식은 실행 지연(수 초 소요), 부분 실패(Partial Failure)로 인한 보안 홀, 타 인스턴스 서비스 장애를 유발함.
- **목적**:
  - `IncidentReport`의 지시어(`QUARANTINE_EC2`, `BLOCK_AND_QUARANTINE`) 수신 즉시 10초 이내에 타깃 EC2를 네트워크 레벨에서 단일 트랜잭션으로 원자적 고립.
  - 인바운드가 전면 차단된 `CloudShield-Quarantine-SG`로 전면 교체하여 제로 트러스트 격리 완결.

---

## 2. 핵심 엔지니어링 설계 및 구현

### 2.1 원자적 전면 교체 (`modify_instance_attribute`)
- **API 채택**: `ec2.modify_instance_attribute(InstanceId=..., Groups=[target_sg_id])`
- **설계 근거**:
  - 기존 보안 그룹 목록을 인자로 전달된 `[target_sg_id]` 단일 배열로 즉각 덮어씀.
  - 규칙을 개별 회수(`revoke_security_group_ingress`)할 필요 없이 단 1회의 AWS API 트랜잭션으로 모든 기존 인/아웃바운드 허용을 무효화.

### 2.2 상태 기반 멱등성 (Idempotency) 보장
- **사전 상태 검사**:
  - `describe_instances`로 인스턴스의 현재 보안 그룹 목록(`current_sgs`)을 조회.
  - 이미 `current_sgs == [target_sg_id]` 상태인 경우 쓰기 API 호출을 생략하고 즉시 `True` 반환.
- **선언적 상태(Desired State) 덮어쓰기**:
  - 동시 호출(Race Condition) 상황에서 2개 이상의 요청이 실행되더라도, `Groups=[target_sg_id]`는 목표 상태를 선언하는 방식이므로 중복 에러 없이 항상 동일한 격리 결과를 보장.

### 2.3 결함 격리 (Fault Isolation)
- 유효하지 않은 인스턴스 ID, 인스턴스 종료 상태, IAM 권한 부족 등으로 인한 `botocore.exceptions.ClientError` 발생 시 예외를 상위 오케스트레이터로 전파하지 않고 `quarantine_applied: False`로 반환하여 전체 파이프라인 중단을 방지.

---

## 3. 기술 검증 및 트레이드오프 분석 (Technical Critique & Q&A)

### 3.1 폭발 반경(Blast Radius) 격리: 보안 그룹 공유 환경에서의 안전성
- **질문/쟁점**: 침해 발생 시 보안 그룹의 Ingress 규칙(22번 등)을 직접 삭제하지 않고 인스턴스의 SG 자체를 교체해야 하는 이유는?
- **기술적 팩트**:
  - AWS 보안 그룹은 1개의 보안 그룹을 **다수의 EC2 인스턴스가 공유**할 수 있는 N:M 구조임.
  - 침해된 1대의 EC2 때문에 기존 보안 그룹의 Ingress 규칙을 삭제하면, 동일 보안 그룹을 공유하는 **정상 운영 중인 나머지 서버들까지 인바운드가 차단되는 대규모 서비스 다운(Blast Radius 확산)**이 발생함.
  - 따라서 인스턴스 레벨에서 보안 그룹 연결을 격리 SG로 교체하는 것이 정상 서비스를 보호하면서 타깃 인스턴스만 핀포인트 고립시키는 유일하게 안전한 방법임.

### 3.2 격리 상태에서의 포렌식 및 사후 조사 접근 경로
- **질문/쟁점**: 격리라는 것이 내부망/외부망 통신을 차단하는 것인데, 격리된 상태에서 보안팀은 어떻게 접속하여 침해 조사를 진행하는가?
- **엔터프라이즈 SecOps 표준 접근 방안**:
  1. **AWS Systems Manager (SSM) Session Manager (권장)**:
     - 22번 포트 등 인바운드 규칙을 일체 열지 않고도, 인스턴스가 SSM 엔드포인트(HTTPS 443)로의 통신(또는 VPC PrivateLink)만 유지되면 AWS 콘솔/CLI에서 IAM 기반으로 안전하게 셸 세션을 열어 라이브 포렌식(메모리 덤프, 프로세스 추적) 수행 가능.
  2. **보안 전용 관리망(Bastion/Forensics Host) 단독 Ingress 허용**:
     - `CloudShield-Quarantine-SG`에 외부망은 전면 차단하되, 보안 관제 점프 호스트(예: `10.0.99.10/32`)에서 오는 트래픽만 예외적으로 허용.
  3. **EBS 볼륨 오프라인 포렌식 (Disk Snapshot)**:
     - 라이브 인스턴스에 직접 접속하지 않고, 타깃 EC2의 EBS 스냅샷을 생성하여 분석 전용 격리 인스턴스에 Read-Only로 마운트하여 정적 증거를 수집.

### 3.3 복구(Rollback) 관점의 현재 한계 및 차기 과제
- **현재 구현의 한계**:
  - `quarantine_ec2_instance`가 원자적 교체를 수행하면서 기존 보안 그룹 목록(`current_sgs`)을 영구 저장하지 않고 덮어씀.
  - 조사 종료 후 정상 복구(Rollback)를 수행할 때 기존 보안 그룹이 무엇이었는지 자동 추적 불가.
- **차기 로드맵 방어 논리**:
  - 본 1차 마일스톤은 "10초 단방향 원자적 침해 차단" 증빙에 집중함.
  - 2차 마일스톤 과제로 교체 직전 `current_sgs`를 EC2 인스턴스 태그(`CloudShield:OriginalSGs`) 또는 DynamoDB 상태 저장소에 보존하고, 사후 복구 자동화 스크립트가 이를 역참조하여 복원하도록 고도화할 계획임.

---

## 4. 테스트베드 검증 결과

`tests/unit/test_remediation.py`에서 moto 기반 가상 AWS 인프라 리소스를 대상으로 검증을 완료함:

| 테스트 함수 | 검증 목적 | 결과 |
| :--- | :--- | :---: |
| `test_find_quarantine_security_group_success` | 표준 네이밍(`CloudShield-Quarantine-SG`) 기반 격리 SG ID 동적 조회 검증 | **PASS** |
| `test_find_quarantine_security_group_not_found` | 미존재 보안 그룹 조회 시 에러 없이 None 반환 검증 | **PASS** |
| `test_quarantine_ec2_instance_success` | 인스턴스 SG가 Quarantine SG 1개로 완전 원자적 교체되는지 실시간 상태 검증 | **PASS** |
| `test_quarantine_ec2_instance_idempotent` | 연속 2회 호출 시 추가 API 호출 생략 및 상태 유지(멱등성) 검증 | **PASS** |
| `test_quarantine_ec2_instance_not_found` | 비존재 인스턴스 ID 전달 시 ClientError 예외 격리 및 False 반환 검증 | **PASS** |
| `test_apply_remediation_quarantine_integration` | IncidentReport(`QUARANTINE_EC2`) 기반 apply_remediation 통합 연동 검증 | **PASS** |
| `test_apply_remediation_action_routing` | `ALERT_ONLY`, `BLOCK_WAF` 등 비대상 액션 인입 시 L4 격리 미실행 라우팅 검증 | **PASS** |

- **품질 게이트 검증 (`powershell .\scripts\check.ps1`)**:
  - 테스트 위치 준수 (100%)
  - Ruff Lint & Format 통과
  - Pytest 89 passed, 4 skipped, 0 failed (100% 통과)
