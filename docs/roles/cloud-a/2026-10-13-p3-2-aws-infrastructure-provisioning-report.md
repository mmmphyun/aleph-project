# [P3-2] 루트 Terraform Egress 결합 및 AWS 인프라 프로비저닝 결과 보고서

- **작성 일시**: 2026-10-13 KST
- **작성자**: 클라우드 A (플랫폼 전담 @mmmphyun)
- **관련 티켓**: [P3-2] [클라우드 A] 루트 Terraform Egress 결합 및 AWS 인프라 프로비저닝 (https://notion.so/3f704d37c2258020ac84f63877c31760)
- **관련 Issue / PR**: Issue #169 / PR #170

---

## 1. 개요 및 배경

P3-1A(Egress 검증 완화) 및 P3-1B(baseline Egress TCP 80/443 정책) 완료에 따라, 루트 Terraform에서 외부 송신 정책을 결합하고 `ap-southeast-2` (시드니) 리전에 단일 10초 관통 대응 데모를 위한 AWS 인프라 전체를 프로비저닝함.

타깃 EC2 부트스트랩 시 패키지 설치(`apt-get`) 및 CloudWatch Agent deb 다운로드/로그 전송에 필요한 최소 Egress 경로(TCP 80/443 -> `0.0.0.0/0`)를 보장하고, 실제 CloudWatch Logs 스트림 수신 여부를 검증함.

---

## 2. 프로비저닝 인프라 사양 및 아키텍처

- **배포 리전**: `ap-southeast-2` (시드니)
- **배포 환경**: `dev`

| 계층 | 리소스 명칭 / 유형 | 논리 식별자 / 스펙 | 비고 |
| :--- | :--- | :--- | :--- |
| **Network** | VPC | `vpc-088f38f763a3632cd` (CIDR: `10.42.0.0/16`) | IGW 및 2-AZ Subnets 구성 |
| **Network** | Baseline SG | `sg-07d8f7ea689ecd95e` | SSH(22), HTTP(80) Ingress / Egress 80, 443 |
| **Network** | Quarantine SG | `sg-075e49d08f46d41de` | 양방향 빈 규칙 (`ingress=[]`, `egress=[]`) |
| **Compute** | Target EC2 | `i-027b9d94be16b0d77` (`t3.micro`) | Ubuntu 22.04 LTS (`ami-075a5b973dac51741`) |
| **State** | DynamoDB | `CloudShield-AuthFailure-Window` | 슬라이딩 윈도우 실패 카운터 및 TTL |
| **Runtime** | Lambda Orchestrator | `CloudShield-Threat-Orchestrator` | Python 3.12, 메모리 256MB, 타임아웃 10s |
| **Security** | WAFv2 WebACL | `8ffb0c27-ad7f-4fec-9c27-e0bd7ff2a751` | Default Allow, Rule 0 Block |
| **Security** | WAFv2 IPSet | `499e3905-10e0-4d91-8a6f-a0a49dec2cc8` | IPv4 REGIONAL /32 차단 목록 |
| **Telemetry** | CloudWatch Log Groups | `/cloudshield/target/auth-log`<br>`/cloudshield/target/nginx-access-log` | 보존 기간 7일 |

> **보안 주의 (Security Notice)**:
> 타깃 EC2의 실제 공인 IP는 Shodan/Bot 탐색 및 크레딧 소진 방지를 위해 Git에 공개하지 않으며, 인프라 배포자(클라우드 A)가 슬랙 비공개 채널(또는 1:1 메시지)로 직접 전달하는 `<TARGET_PUBLIC_IP>` 값을 사용함.

---

## 3. 루트 Terraform Egress 결합 및 정규화 상세

### 3.1 Egress 결합 (`main.tf`)
- `module "baseline_external_policy"` (`./modules/quarantine_sg/policies/external_bootstrap`) 선언.
- `module "quarantine_sg"`의 `traffic.egress`에 해당 정책 출력을 명시적으로 바인딩:
  ```hcl
  traffic = {
    ingress = var.quarantine_traffic.ingress
    egress  = module.baseline_external_policy.egress
  }
  ```

### 3.2 변수 기본값 동기화 (`variables.tf`)
- 루트 `quarantine_traffic.egress` 기본값을 기존 넓은 대역(`10.42.0.0/16`, 1~65535)에서 P3-1B 신설 규칙인 `package_http`(TCP 80), `agent_logs_https`(TCP 443)로 전면 교체하여 일관성 유지.

### 3.3 AWS IAM API 제약조건 준수 정규화 (`modules/lambda/main.tf`)
- AWS IAM API의 Role 및 Policy Description 필드는 특정 ASCII/Latin-1 정규식 패턴(`[\u0009\u000A\u000D\u0020-\u007E\u00A1-\u00FF]*`)만 허용하므로, 기존 한글 설명을 영문 ASCII로 정규화하여 `ValidationError: 400` 방지.

---

## 4. 실기기 부트스트랩 및 원격 텔레메트리 실측 결과

1. **EC2 UserData 및 부트스트랩 완료**:
   - `apt-get` 의존성 설치, Nginx 기동 및 CloudWatch Agent deb 패키지 정상 다운로드·설치 완료.
2. **CloudWatch Logs 수신 검증**:
   - 로그 그룹 `/cloudshield/target/auth-log` 내 인스턴스 전용 스트림(`i-027b9d94be16b0d77`) 자동 생성 확인.
   - SSH 데몬 시작 및 시스템 로그 이벤트 실측 확인:
     - `sshd[713]: Server listening on 0.0.0.0 port 22.`
     - 수집 타임스탬프와 인입 시간의 일치성 확인.

---

## 5. 팀원별 실증 가이드 (P3-3, P3-4 착수 안내)

### 5.1 네트워크 담당 (P3-3: 시나리오 1 Kali/Hydra 공격 및 L4 단절 실측)
- **AWS 접근 권한**: AWS Console 및 CLI 설정 **불필요** (Blackbox 공격자 관점 유지).
- **타깃 정보**:
  - 타깃 호스트: `<TARGET_PUBLIC_IP>` (슬랙 비공개 채널 또는 1:1 메시지로 전달된 공인 IP)
  - 포트: TCP 22 (SSH)
- **실증 절차**:
  1. 로컬 Kali/WSL 환경에서 Hydra 모의 공격 스크립트 실행 (예: 5회 이상 실패 유발).
  2. 동시 로컬 Wireshark 또는 tcpdump 패킷 캡처 수행.
  3. 5회 누적 실패 후 Lambda가 타깃 EC2의 SG를 격리 SG(`sg-075e49d08f46d41de`)로 변경함.
  4. 이후 공격 트래픽의 TCP RST/Timeout 및 신규 SYN 연결 드롭을 패킷 타임라인으로 실측하여 보고서 작성.

### 5.2 클라우드 B 담당 (P3-4: 수집 지연 계측 및 Slack 카드 전파 실측)
- **AWS 접근 권한**: CloudWatch Logs 읽기(Read-only) 관측 필요.
- **모니터링 대상**:
  - 로그 그룹: `/cloudshield/target/auth-log`
  - 구독 필터: `CloudShield-SSH-FailedPassword-Filter`
  - Lambda: `CloudShield-Threat-Orchestrator`
- **실증 절차**:
  1. 네트워크 팀의 Hydra 공격 발생 시각($T_{attack}$) 기록.
  2. CloudWatch Logs 스트림의 $T_{event}$ 및 $T_{ingest}$ 차이 계측 (버퍼링 지연 측정).
  3. Lambda 오케스트레이터 호출 후 지정된 Slack 채널로 침해 상황 알림 카드가 도착하는 최종 시각($T_{slack}$) 계측.
  4. 단일 10초 관통 SLA 충족 여부를 분석하여 실측 보고서 작성.
