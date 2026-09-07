# CloudShield: 프로젝트 에이전트 헌법 및 작업 지침 (AI Working Agreement)

너는 CloudShield(클라우드 하이브리드 위협 탐지·자동 대응 및 SecOps 파이프라인) 프로젝트의 팀원이다.
모든 코딩 에이전트는 본 헌법의 규정을 무조건적으로 준수해야 한다.

---

## 1. 프로젝트 정체성 및 핵심 목표

* **단일 10초 관통 데모 파이프라인**:
  - 웹/UI 개발 매몰을 방지하고, 실제 클라우드 인프라 침해 위협에 대한 10초 관통 자동 대응 능력을 증빙함.
  - 흐름: `공격 발생(Hydra/Nmap) -> 타깃 서버(EC2) -> CW Agent 중앙 수집 -> Lambda 오케스트레이터(시그니처/LLM) -> 다중 계층 원자적 차단(L4 SG / L7 WAF / IAM 세션) -> Slack 상황 전파`.

---

## 2. R&R 경계선 및 직무별 포트폴리오 지분 절대 침범 금지

에이전트는 프롬프트를 수행할 때 **의뢰자의 담당 직무 영역 외 타 팀원의 고유 포트폴리오 영역을 절대 침범하거나 임의로 코드를 작성·수정하지 않는다.**

```text
[직무별 고유 도메인 영역 - 면접 핵심 무기: 상호 침범 절대 금지]
1. 네트워크: 모의 공격 스크립트, tcpdump/Wireshark L4 패킷 플래그 분석 보고서 (network/, docs/roles/network/)
2. 클라우드 B: CW Agent 수집 설정, Slack Block Kit 알림 모듈 (src/collector/, src/reporter/, docs/roles/cloud-b/)
3. 보안: 정규식 시그니처 룰(rules.py), LLM Few-shot 프롬프트/분석기 (src/detection/, docs/roles/security/)

[클라우드 A 전담 플랫폼 영역 - 엔지니어링 깊이 확보]
- 공통 데이터 인터페이스 계약 (src/contracts/)
- Lambda 런타임 오케스트레이터 및 Boto3 원자적 복합 차단 엔진 (src/remediation/)
- Terraform IaC 모듈화 및 Trivy 검증 (infra/)
- GitHub Actions OIDC 무인증 CI/CD 파이프라인 (.github/)
- moto 기반 가상 AWS 테스트베드 및 개발 하네스 (tests/)
- 플랫폼 아키텍처 문서 (docs/roles/cloud-a/)

[팀 공통 협업 문서 영역 - 자유 작성 허용]
- 팀 회의록 (docs/shared/meetings/)
- 아이디어 및 기획 (docs/shared/ideas/)
```

### 2.1 세션 시작 시 역할 자동 인식 및 스코프 잠금 (Role-Lock)
에이전트는 세션 시작 즉시 다음 우선순위로 사용자의 역할을 확정하고 허용된 디렉토리 외 모든 파일 수정을 자동 차단(Lock)한다:
1. **1순위 (로컬 자동 인식)**: 프로젝트 루트의 `.agent-role` 파일 내용 확인 (`network`, `cloud-b`, `security`, `cloud-a`).
2. **2순위 (프롬프트 수동 명시)**: 사용자의 첫 메시지에 포함된 직무 태그 확인 (`[보안] ...`, `나 네트워크 담당인데 ...`).
3. **3순위 (역질문 강제)**: 1, 2순위 모두 없을 경우 에이전트는 코드를 작성하지 말고 첫마디로 *"담당 직무(네트워크/클라우드 B/보안/클라우드 A)가 무엇인가요?"*를 역질문하여 역할을 확정한 뒤 착수한다.
4. **설명 선행 원칙**: 코딩을 시작하기 전, 해당 작업의 핵심 개념과 원리를 사용자에게 2~3줄로 먼저 설명하여 담당자의 기술 이해도 및 면접 역량을 지원한다.
5. **노션 시작 전 티켓 연동**: 새 작업 착수 시 `node scripts/get_my_tasks.js`를 실행하여 노션 [프로젝트 일정] DB의 `[시작 전]` 티켓을 자동 조회하고, 일치하는 티켓 링크를 GitHub Issue 본문에 자동 포함하여 칸반 보드를 `[진행 중]`으로 자동 전이시킨다.

### 2.2 경계선 파일 단일 소유권 매트릭스 (Single Ownership Matrix)
직무 간 경계가 모호한 설정 및 명세 파일은 단일 소유자 원칙에 따라 아래 지정된 직무 외에는 임의 수정할 수 없다:
| 경계선 파일 / 리소스 | 단독 책임 직무 | 협업 및 연계 방식 |
| :--- | :---: | :--- |
| `amazon-cloudwatch-agent.json` | **클라우드 B** | 로그 수집 경로 확정 후 EC2 인스턴스에 배포 |
| `nginx.conf` (Web 타깃 설정) | **클라우드 B** | 80/443 포트 및 수집 로깅 포맷 정의 |
| 격리 Security Group 규칙 명세 | **네트워크** | 네트워크 담당이 인/아웃바운드 명세 작성 $\rightarrow$ 클라우드 A가 Terraform 코드로 변환 |
| AWS WAF IPSet 명세 | **보안** | 차단 정책 명세 $\rightarrow$ 클라우드 A가 Boto3/Terraform 엔진으로 구현 |

---

## 3. 절대 동결 및 수정 금지 파일 (Protected Contracts)

다음 파일 및 경로는 클라우드 A(테크 리드)의 명시적 지시 없이 **어떤 에이전트도 절대 임의 수정할 수 없다.**
- `src/contracts/*.py` (IncidentReport, Events 모델)
- `tests/test_contracts.py` (인터페이스 계약 불변성 검증 테스트)
- `tests/mock_data/**` (공통 표준 모의 데이터셋)
- `.github/workflows/*.yml` (CI/CD 파이프라인)
- `pyproject.toml` (공통 프로젝트 의존성)

---

## 4. Git 브랜치 및 커밋 메시지 컨벤션

### 4.1 브랜치 전략
- `feat/<직무>-<기능명>` (예: `feat/security-rules-engine`, `feat/cloud-b-slack-card`)
- `fix/<이슈명>`
- `chore/<작업명>`

### 4.2 커밋 메시지 컨벤션
- 형식: `<type>(<scope>): <한글 요약>` (마침표 없음)
- Type: `feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `style`, `perf`, `ci`
- Scope: 반드시 담당 직무 및 도메인 명시
  - `contract`: 공통 인터페이스 규격
  - `cloud-a`: 오케스트레이터 및 복합 차단 엔진
  - `cloud-b`: 로그 수집 및 Slack 알림
  - `security`: 시그니처 룰 및 LLM 분석 엔진
  - `network`: 모의 공격 및 패킷 분석
  - `infra`: Terraform IaC
- 예시: `feat(security): SSH 무차별 대입 1차 시그니처 룰 구현`

---

## 5. 코드 주석 및 엔지니어링 표준

- **언어**: 한국어 (프로덕션급 기술 주석)
- **금지**: 단순 코드 동작 읊기, 튜토리얼식 설명.
- **필수 포함 항목**:
  1. **Why**: 해당 로직/라이브러리를 채택한 비즈니스 및 아키텍처적 이유.
  2. **Constraints**: 매개변수 유효성 제약조건, 단위, 정규식 규격.
  3. **Side-effects / Edge-cases**: 외부 API 호출, 예외 발생 조건, 동시성 주의사항.

### 5.1 직무별 산출물 특화 엔지니어링 표준 (Domain-specific Standards)
1. **네트워크 (`network/`)**:
   - 모의 공격 셸 스크립트 작성 시 비정상 종료 방지 및 안전성 플래그(`set -euo pipefail`) 필수 적용.
   - Wireshark/tcpdump 분석 보고서 작성 시 단순 패킷 나열을 금지하고, L4 TCP 플래그(SYN, ACK, RST), 3-Way Handshake 타임라인, 공격 페이로드의 비정상 패턴을 마크다운 표로 구조화.
2. **보안 (`src/detection/`)**:
   - 정규식 시그니처 룰 작성 시 ReDoS(Catastrophic Backtracking) 방어 구조를 적용하고, 정규식 설계 근거(Why) 및 매칭 복잡도를 주석으로 명시.
   - LLM Few-shot 프롬프트 작성 시 `IncidentReport` 스키마와 완벽히 호환되는 엄격한 JSON 구조 출력 강제.
3. **클라우드 B (`src/collector/`, `src/reporter/`)**:
   - CloudWatch Agent 구성 파일(`amazon-cloudwatch-agent.json`) 작성 시 JSON 문법 및 타깃 로그 경로 유효성 검증.
   - Slack Block Kit 알림 카드 페이로드 작성 시 필드별 500자 초과 방지 안전 자르기(Truncate) 및 필수 키(`incident_id`, `rule_name`, `source_ip`, `remediation_action`) 누락 방지.
4. **클라우드 A (`src/remediation/`, `src/contracts/`, `infra/`)**:
   - Boto3 차단 API 호출 시 `botocore.exceptions.ClientError` 정밀 핸들링 및 멱등성(Idempotency) 보장.
   - 모든 차단 엔진 및 인프라 코드는 `moto` 기반 가상 AWS 테스트베드에서 100% 검증 가능하도록 작성.

---

## 6. 테스트 및 품질 검증 원칙

- 신규 기능 구현 또는 버그 수정 시 반드시 `tests/` 디렉토리에 `pytest` 테스트 코드를 함께 작성한다.
- 작업 완료 전 다음 명령어를 반드시 통과해야 한다:
  ```powershell
  uv run ruff check .
  uv run ruff format --check .
  uv run pytest
  ```
- 테스트를 통과시키기 위해 기존 검증 로직이나 제약조건을 임의 삭제하는 행위를 엄격히 금지한다.

---

## 7. 안전 및 보안 규칙

1. `main` 브랜치에 직접 push하지 않는다.
2. AWS Access Key, Secret Key, API 토큰 등 자격증명을 절대 하드코딩하거나 커밋하지 않는다.
3. 실제 인프라 변경 코드는 사전 승인된 영향 범위(단일 테스트 VPC/계정) 내로 제한한다.
4. 로컬 개발 및 테스트 시에는 `moto` 기반의 가상 Mock 환경을 우선 활용한다.
