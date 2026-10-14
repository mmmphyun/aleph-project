# [P3-3B] 모의 공격자 Kali 공인 IP 인바운드 개방 및 Baseline SG 롤백 실측 보고서

- **작성 일시**: 2026-10-14 KST
- **작성자**: 클라우드 A (플랫폼 전담 @mmmphyun)
- **관련 티켓**: [P3-3B] [클라우드 A] 모의 공격자 Kali 공인 IP 인바운드 개방 및 Baseline SG 롤백 절차 준비 (https://notion.so/3f804d37c22580619eadd419c2cb31af)
- **관련 Issue**: Issue #175 (브랜치: `feat/cloud-a-baseline-sg-ingress-rollback`)

---

## 1. 개요 및 배경

시나리오 1(SSH 무차별 대입 공격 및 L4 다중 계층 자동 대응)의 단일 10초 관통 대응을 실인프라에서 증빙하기 위해, 외부 모의 공격자(Kali Linux)의 접근 경로를 선별 개방하고 침해 후 격리된 타깃 인프라를 즉각 복원하는 원자적 롤백 체계를 구축함.

1. **공격자 인바운드 트래픽 개방**: 네트워크 담당자의 Kali 공인 IPv4(/32)를 Baseline Security Group에 조건부 주입하여 실서버 침해 트래픽 수용.
2. **원자적 롤백 도구 구축**: L4 격리(Quarantine SG) 이후 운영 기준선 보안 그룹(Baseline SG)으로 즉시 복구하는 Boto3 스크립트(`scripts/restore_baseline_sg.py`) 및 회귀 테스트 슈트 개발.
3. **실인프라 관통 실측 검증**: 5회 인증 실패 도달 시점부터 격리 SG 부착 및 Slack 상황 전파, 롤백까지의 8대 타임스탬프를 정밀 계측하여 10초 관통 대응 SLA를 실증함.

---

## 2. 모의 공격자 IP 인바운드 배포 (보안 거버넌스 준수)

공격자의 실제 공인 IP가 Git 저장소에 평문으로 커밋되는 보안 사고를 차단하기 위해, 로컬 환경 변수 분리 정책을 100% 준수함.

- **배포 방식**: `.gitignore`로 보호되는 로컬 `infra/terraform/terraform.tfvars`의 `quarantine_traffic.ingress`에 Kali IP 주입:
  ```hcl
  "ssh_kali" = {
    cidr        = "<KALI_PUBLIC_IP>/32"
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    description = "Kali Linux SSH attack access"
  }
  ```
- **원자적 타깃 배포**: EC2 인스턴스 재생성(User-data 해시 변경) 위험을 방지하기 위해 `terraform apply -target="module.quarantine_sg"`를 적용하여 기존 Baseline SG(`sg-07d8f7ea689ecd95e`)의 Ingress 규칙만 인플레이스(In-place) 업데이트 완료.

---

## 3. 원자적 롤백 복구 엔진 구현 (`scripts/restore_baseline_sg.py`)

L4 격리 실측 직후 타깃 EC2의 정상 통신을 즉시 재개하기 위한 복구 엔진을 개발함.

### 3.1 기술적 원리 및 핵심 설계
1. **무상태 원자적 교체**: 외부 캐시 없이 `describe_instances`로 인스턴스의 현재 보안 그룹을 조회하고, `modify_instance_attribute(Groups=[baseline_sg_id])`를 통해 단일 Baseline SG로 원자적 대체.
2. **동기 확증(Read-after-Write Verification)**: 교체 API 호출 직후 인스턴스 보안 그룹을 즉시 재조회하여 `baseline_sg_id` 포함 여부를 검증한 후 완료 상태(`status: success`) 확정.
3. **상태 기반 멱등성(Idempotency)**: 이미 Baseline SG가 단독 적용된 상태인 경우 불필요한 API 호출을 생략하고 `status: unchanged`를 즉각 반환.
4. **결함 전파(Failure Escalation)**: Boto3 호출 중 `ClientError` 발생 시 무음 실패를 차단하고 0이 아닌 종료 코드(`sys.exit(1)`)로 예외 전파.

### 3.2 단위 테스트 슈트 검증 (`tests/unit/test_restore_baseline_sg.py`)
- `mock_aws` 기반 가상 환경에서 격리 상태 인스턴스의 정상 복구, 멱등 처리, 인스턴스 미존재 예외 처리 등 4개 테스트 케이스 100% 통과.

---

## 4. 시나리오 1 실인프라 관통 대응 실측 결과 (INC-1791953271-2171)

2026-10-14 13:47 KST에 실행된 실인프라 모의 공격에 대해 클라우드 A가 계측한 5대 핵심 지표 결과임.

| 지표명 | 계측 대상 및 기준 | 시각 (KST) | Epoch (ms) | 소요 시간 및 상세 |
| :--- | :--- | :---: | :---: | :--- |
| **`T_auth`** | 5회차 인증 실패 OS 기록 | 13:47:48.911 | 1791953268911 | sshd[10056] auth.log 기록 시각 |
| **`T_cw`** | 5회차 CW Logs 수집 인입 | 13:47:50.853 | 1791953270853 | CW 수집 지연: **1.942초** |
| **`T_block`** | Lambda 오케스트레이터 기동 | 13:47:50.994 | 1791953270994 | 기동 ~ 완료(13:47:54.216, 소요: **3.22초**) |
| **`T_sg_verified`**| 타깃 EC2 격리 SG 부착 확정 | 13:47:52.500 | 1791953272500 | `sg-075e49d08f46d41de` 교체 집행 |
| **`T_restored`** | Baseline SG 롤백 복구 완료 | 13:52:28.594 | 1791953548594 | `sg-07d8f7ea689ecd95e` 복원 (소요: **1.74초**) |

### 4.1 단일 10초 관통 대응 성과 판정
- **실측 대응 시간**: `T_auth (13:47:48.911)` $\rightarrow$ `T_sg_verified (13:47:52.500)`: **총 3.589초**.
- **목표 대비 달성률**: 프로젝트 핵심 목표인 **10초 이내 완전 자동 차단 SLA를 35.9% 수준으로 초과 달성**함.
- **다중 계층 복합 조치**:
  - L4 계층: EC2 보안 그룹 전면 차단 (`sg-075e49d08f46d41de`).
  - L7 계층: WAFv2 IPSet에 공격자 IP(`/32`) 차단 명단 등록.
  - 전파 계층: SecOps Slack 채널에 침해 분석 및 대응 알림 카드 전파 완료 (`INC-1791953271-2171`).

---

## 5. 타깃 서버 환경 보정 및 사전 세팅 동기화

실측 과정에서 발견된 `invalid user` 로그 분석을 통해 타깃 EC2의 `cloudshield_test` 계정 미반영 상태를 확인하고 후속 실측을 위해 즉시 동기화함.

- **조치 내역**: EC2 Instance Connect 임시 인증 세션을 수립하여 타깃 서버에 `init_target_server.sh`를 전송 및 루트 권한으로 실행 완료.
- **적용 결과**:
  - `cloudshield_test` 계정 정상 생성 (`uid=1001`, 상태 `P` 잠금 해제).
  - OpenSSH Match 블록 정책 정상 바인딩 (`PasswordAuthentication yes`, `AuthenticationMethods password`).
  - Nginx 헬스체크 및 포트 22/80 정상 리스닝 확인.

---

## 6. 결론 및 향후 계획

1. **P3-3B 목표 달성**: 공격자 접근로 개방, 원자적 롤백 도구 구축, 3.589초 관통 대응 및 1.74초 롤백 실측을 성공적으로 완료함.
2. **후속 연계**:
   - 네트워크 담당자의 `P3-3C` (L4 패킷 단절 pcap 분석) 머지 대기.
   - 클라우드 B 담당자의 `P3-4` (수집 지연 및 Slack 전파 실측) 머지 연계.
   - Phase 3 후속 과제인 `P3-5` (ALB 인프라 구축 및 L7 WAF 실제 트래픽 차단 연동) 착수 준비.
