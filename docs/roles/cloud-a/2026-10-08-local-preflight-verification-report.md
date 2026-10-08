# CloudShield 인프라 배포 전 로컬 3단계 정밀 검증 보고서 (Local Pre-flight Gate)

- **검증 일시**: 2026-10-08
- **검증 환경**: Windows 11 호스트 / Docker Desktop (Linux 컨테이너) / Terraform v1.16.5 / Trivy v0.75.0
- **원칙**: 저장소 무오염(Zero Git Footprint), 원자적 단계별 실측 검증
- **작성자**: 클라우드 A (플랫폼 전담 @mmmphyun)

---

## 검증 진행 매트릭스

| 단계 | 세부 작업 | 최종 상태 | 실측 결과 요약 |
| :---: | :--- | :---: | :--- |
| **1-A** | Lambda 배포 패키지(`orchestrator.zip`) 생성 및 구조 점검 | **완료 (PASS)** | `x86_64-unknown-linux-gnu` 기본 빌드 (2.60MB) |
| **1-B** | Docker 공식 Lambda Linux 런타임 C-Extension 로드 검증 | **완료 (PASS)** | `public.ecr.aws/lambda/python:3.12` 내 핸들러 임포트 성공 |
| **2-A** | 시나리오 1 (SSH) Raw `auth.log` 역주입 매트릭스 검증 | **완료 (PASS)** | `mock_auth.log` 전수 파싱, Spraying 탐지, 오탐 0건 |
| **2-B** | 시나리오 2 (Web) Raw `nginx-access.log` 역주입 매트릭스 검증 | **완료 (PASS)** | 3종 Web 공격(PT, Probing, Scan) 탐지, 오탐 0건 |
| **3-A** | Terraform 모듈 및 루트 구문 무결성 (`fmt`, `init`, `validate`) | **완료 (PASS)** | 결함 수정 후 `Success! The configuration is valid.` |
| **3-B** | Trivy IaC 정적 보안 및 최소 권한(PoLP) 스캔 | **완료 (PASS)** | CRITICAL/HIGH 0건, LOW 2건 (의도된 기본 KMS) |

---

## 1단계 상세 실측 결과: Lambda 아티팩트 ABI 및 Linux 런타임 호환성

### 1-A. 아티팩트 빌드 무결성
- **명령**: `uv run python scripts/package_lambda.py` (기본 타깃 플랫폼: `x86_64-unknown-linux-gnu`)
- **산출물**: `infra/terraform/modules/lambda/build/orchestrator.zip` (2,603,646 bytes, Linux 64-bit 휠 포함)
- **Git 무오염 여부**: `.gitignore` 등록 경로로 `git status` 변경점 0건 유지.

### 1-B. Linux 컨테이너 내부 실행 검증
- **검증 환경**: `public.ecr.aws/lambda/python:3.12` 공식 베이스 이미지 (Linux x86_64, glibc 기반)
- **실행 명령**:
  ```bash
  python -m zipfile -e orchestrator.zip .
  python -c "import pydantic_core; from remediation.orchestrator import threat_orchestrator_handler; print('SUCCESS_LOAD_OK', threat_orchestrator_handler)"
  ```
- **실측 결과**: `SUCCESS_LOAD_OK <function threat_orchestrator_handler at 0x71ed09473c40>`
- **판정 (PASS)**:
  - C-Extension 바이너리가 AWS Lambda Linux 환경에서 정상 동적 링킹됨을 증빙.
  - Windows 호스트 빌드로 인한 Linux 환경 라이브러리 누락 가능성 원천 배제.

---

## 2단계 상세 실측 결과: 네트워크 모의 산출물 Raw 로그 역주입 매트릭스

### 2-A. 시나리오 1 (SSH) Raw Log 전수 검증
- **검증 대상**: `tests/mock_data/mock_auth.log`, `tests/mock_data/mock_auth_noisy.log`
- **실측 결과**:
  - `mock_auth.log`: 5개 원시 라인 파싱 $\rightarrow$ 다중 계정 분산 공격 감지 $\rightarrow$ `SSH_PASSWORD_SPRAYING` 판정 $\rightarrow$ `BLOCK_IP_ONLY` (MITRE `T1110.003`) 정확 매핑.
  - `mock_auth_noisy.log`: 총 13개 라인 중 SSH 실패 6건 정확 파싱, 비실패 라인 7건(Accepted publickey, New session, sudo, Connection closed, Accepted password, Received disconnect, Disconnected) 완벽 무시 (오탐 0건). 추가로 `session opened/closed` 라인에 대해서도 개별 assert로 무시 여부 검증 완료.
- **판정 (PASS)**: 정규식 파서와 룰 엔진의 오탐/미탐 무결성 확인.

### 2-B. 시나리오 2 (Web) Raw Nginx Log 전수 검증
- **검증 대상**: Nginx `cloudshield_combined` 규격 원시 로그 (Curl, Gobuster 실측 포맷)
- **실측 결과**:
  - `Path Traversal` (`GET /../../etc/passwd`): 즉시 탐지 $\rightarrow$ `BLOCK_WAF` (MITRE `T1595.002`).
  - `Sensitive File Probing` (`GET /.env`): 즉시 탐지 $\rightarrow$ `BLOCK_WAF` (MITRE `T1595.003`).
  - `Web Directory Scanning` (Gobuster 5개 후보 탐색): 10초 윈도우 집계 탐지 $\rightarrow$ `BLOCK_WAF` (MITRE `T1595.003`).
  - `정상 트래픽` (`/index.html`, `/health` 등 4건): 0건 탐지 (정상 트래픽 오탐 0건).
  - Pydantic 엄격 검증: EC2 인스턴스 ID의 17자리 16진수(`i-[0-9a-f]{17}`) 형식 검증 정상 작동 확인.
- **판정 (PASS)**: 웹 3대 위협 탐지 및 정규화 체인의 무결성 확인.

---

## 3단계 상세 실측 결과: Terraform IaC 구문 무결성 및 Trivy 보안 검사

### 3-A. Terraform 구문 검증 및 결함 픽스
- **수정 전 결함**:
  - `modules/lambda/main.tf` 133행에서 미선언 리소스 `aws_iam_policy.least_privilege.arn` 참조로 `terraform validate` 실패.
- **수정 조치**:
  - 133행 참조를 `aws_iam_policy.lambda_least_privilege.arn`으로 교체.
  - `terraform fmt -recursive` 적용.
  - `terraform providers lock -platform=windows_amd64 -platform=linux_amd64` 실행하여 크로스 플랫폼 락 확보.
  - 회귀 방지용 pytest 테스트(`test_terraform_lambda_iam_policy_attachment_references_declared_policy`) 신설.
- **재검증 결과**:
  ```text
  Success! The configuration is valid.
  ```
- **판정 (PASS)**: 루트 모듈과 Phase 1 모듈(DynamoDB, Lambda)의 IaC 배포 문법 무결성 100% 확보.

### 3-B. Trivy IaC 정적 보안 스캔 (`trivy config infra/terraform`)
- **결과**:
  - CRITICAL: 0건
  - HIGH: 0건
  - MEDIUM: 0건
  - LOW: 2건
    - `AWS-0025 (DynamoDB)`: 테이블 암호화에 CMK 대신 AWS 관리형 기본 KMS 키(Default KMS Key) 사용.
    - `AWS-0017 (CloudWatch Logs)`: 로그 그룹에 KMS CMK가 미연결된 CloudWatch 기본 AES-256 서버사이드 암호화 적용.
- **판정 (PASS)**: 데모 환경 비용 절감을 위해 기본 암호화 설정을 채택한 기설계 사항과 일치함.

---

## 4단계: 전체 회귀 검증 (`check.ps1`)
- **실행 결과**: 800 items passed, 1 warning (pytest-socket 소켓 차단 검증), exit code 0.
- **최종 상태**: Python 도메인 로직, 데이터 계약, 런타임 ABI, 원시 로그 파싱, Terraform HCL 구문 검증 전 단계 통과.
