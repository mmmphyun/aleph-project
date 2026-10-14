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

## 4. 시나리오 1 실인프라 관통 대응 실측 결과 (INC-1791953271-2171)

2026-10-14 13:47 KST에 실행된 실인프라 모의 공격에 대해, 네트워크 담당자의 pcap 패킷 분석 결과와 클라우드 A/B 계측값을 결합한 **종합 8대 지표 완전체 타임라인**임.

| 순서 | 지표명 | 계측 대상 및 기준 | 시각 (10/14 KST) | 정밀도 / 출처 | 구간 소요 시간 |
| :---: | :--- | :--- | :---: | :--- | :---: |
| 1 | **`T_attack`** | Hydra 최초 SYN 패킷 송신 | **13:47:30.452** | pcap 캡처 (네트워크 전달값) | 기준점 (0.000s) |
| 2 | `T_auth(1)` | 서버 1회차 인증 실패 기록 | 13:47:35.592 | syslog auth.log | +5.140s |
| 3 | **`T_auth(5)`** | 서버 5회차 인증 실패 (임계치 도달) | **13:47:48.911** | syslog auth.log | +18.459s (공격자 전송) |
| 4 | **`T_cw(5)`** | CloudWatch Logs 수집 인입 | **13:47:50.853** | CW ingestionTime | +1.942s (수집 지연) |
| 5 | **`T_block`** | Lambda 오케스트레이터 기동 | **13:47:50.994** | Lambda START | +0.141s (트리거) |
| 6 | **`T_sg_verified`**| 타깃 EC2 격리 SG 교체 확정 | **13:47:52.500** | Boto3 교체 검증 | +1.506s (L4 격리 집행) |
| 7 | **`T_cut`** | 공격자 측 패킷 단절 (최초 무응답) | **13:47:54.388** | pcap 캡처 (네트워크 전달값) | +1.888s (패킷 드롭) |
| 8 | **`T_slack`** | SecOps Slack 알림 카드 도착 | **13:47:54.092** | Slack ts: 1791953274.092879 (클라우드 B 실측값) | +5.182s (임계치 대비 전파 지연) |
| 9 | **`T_restored`** | Baseline SG 롤백 복구 완료 | **13:52:28.594** | 복구 스크립트 계측 | 1.740s 만에 복구 |
| 10 | `Kali 재연결` | 타깃 EC2 정상 통신 재개 확인 | **14:35:23.944** | Kali 재연결 (네트워크 전달값) | 통신 정상화 확인 |

### 4.1 단일 10초 관통 대응 성과 판정 (정확히 5.477초 소요)

- **공식 관통 대응 시간 (임계치 도달 $\rightarrow$ 물리적 패킷 단절)**:
  - 산출식: `T_cut (13:47:54.388)` - `T_auth(5회차) (13:47:48.911)` = **정확히 5.477초 (5,477 ms)**.
  - **SLA(10.0초 이내) 대비 54.8% 수준으로 10초 관통 자동 대응 목표를 완벽히 달성함**.

- **파이프라인 구간별 지연 시간 분해**:
  1. **로그 수집 지연 (`T_auth` $\rightarrow$ `T_cw`)**: `1,942 ms` (CW Agent의 커널 로그 버퍼링 및 AWS 전송).
  2. **오케스트레이터 트리거 (`T_cw` $\rightarrow$ `T_block`)**: `141 ms` (Subscription Filter 이벤트 즉시 디스패치).
  3. **분석 및 L4 격리 집행 (`T_block` $\rightarrow$ `T_sg_verified`)**: `1,506 ms` (DynamoDB 슬라이딩 윈도우 판정 및 Boto3 원자적 SG 교체).
  4. **인프라 전파 및 패킷 드롭 (`T_sg_verified` $\rightarrow$ `T_cut`)**: `1,888 ms` (AWS 하이퍼바이저 보안 그룹 규칙 물리 동기화 및 패킷 드롭).
  - $\rightarrow$ **합계: 5,477 ms (5.477초)**.

- **네트워크 단절 증빙 (네트워크 담당자 실측 연계)**:
  - 연결 탐침 결과: L4 차단 전 24회 정상 연결 성공 후, 차단 시점 이후 **36회 연속 연결 타임아웃** 관측으로 실제 패킷 차단 확증.
  - 복구 후 통신 정상화: 14:35:23.944에 Kali 환경에서 타깃 TCP 22 정상 재연결을 독립 확인 완료.

- **SecOps 상황 전파 지연 (클라우드 B 실측 연계)**:
  - Slack 원본 타임스탬프(`ts: 1791953274.092879`, 13:47:54.092879 KST) 검증 완료.
  - 5회차 인증 실패 시점(`T_auth(5)`) 대비 상황 전파 소요 시간: **5.182초**.
  - 인프라 패킷 차단(`T_cut`: 13:47:54.388)보다 약 0.296초 앞서 Slack 카드가 디스패치되어 차단 집행과 전파가 실시간 병렬 완수됨.
  - 최초 공격 개시(`T_attack`: 13:47:30.452) 기준으로는 23.640초가 소요되었으나, 이는 1-4회 오입력을 관찰하는 슬라이딩 윈도우 수집 구간(18.459초)이며, 침해 임계치 충족 기준 자동 대응 SLA(10초)는 5.477초로 완벽히 충족함.

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
