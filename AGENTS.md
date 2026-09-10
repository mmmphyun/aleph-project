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
1. 네트워크: 모의 공격 스크립트, 패킷 분석 보고서, 네트워크 단위 테스트 (network/, tests/unit/test_network.py, docs/roles/network/)
2. 클라우드 B: CW Agent 설정, Slack 카드 알림 모듈, 수집/리포터 단위 테스트 (src/collector/, src/reporter/, tests/unit/test_collector.py, tests/unit/test_reporter.py, docs/roles/cloud-b/)
3. 보안: 정규식 시그니처 룰, LLM 분석기, 탐지 단위 테스트 (src/detection/, tests/unit/test_rules.py, tests/unit/test_llm_analyzer.py, docs/roles/security/)

[클라우드 A 전담 플랫폼 영역 - 엔지니어링 깊이 확보]
- 공통 데이터 인터페이스 계약 (src/contracts/)
- Lambda 런타임 오케스트레이터 및 Boto3 원자적 복합 차단 엔진 (src/remediation/, tests/unit/test_remediation.py)
- Terraform IaC 모듈화 및 Trivy 검증 (infra/)
- GitHub Actions OIDC 무인증 CI/CD 파이프라인 (.github/)
- moto 기반 가상 AWS 테스트베드 및 개발 하네스 (tests/conftest.py, tests/test_contracts.py, tests/mock_data/)
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
5. **노션 연동 책임 분리 및 에이전트 수정 금지 원칙**:
   - **조회(Read-only)**: 새 작업 착수 시 `node scripts/get_my_tasks.js` 또는 MCP를 통해 노션 [프로젝트 일정] DB의 `[시작 전]` 티켓을 조회하고, 일치하는 티켓 링크를 GitHub Issue 본문에 포함한다.
   - **상태 전이(Write 전담)**: 칸반 보드의 상태 전이(`[시작 전]` $\rightarrow$ `[진행 중]` $\rightarrow$ `[검토 중]` $\rightarrow$ `[완료]`)는 **GitHub Actions(`notion_sync.yml`)가 100% 자동 전담**한다.
   - **에이전트 조작 금지**: 에이전트는 노션 카드의 상태나 속성을 직접 변경하는 MCP 도구(`API-patch-page` 등)를 절대로 호출하지 않는다 (이중 쓰기 방지).
   - **Fallback (노션 API 미설정/조회 실패 시)**: 노션 API 키가 없는 경우에도 GitHub Issue 생성(`gh issue create`)은 필수이며, 작업자는 웹 브라우저에서 해당 노션 일감 카드 URL을 직접 복사하여 Issue/PR 본문에 반드시 기재한다.

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

## 4. 작업 라이프사이클 및 협업 컨벤션

### 4.1 작업 착수 표준 파이프라인 (WIP 1개 제한 원칙)
모든 에이전트와 작업자는 새 작업 착수 시 다음 절차를 엄격히 준수한다:
1. **0단계 (WIP 사전 검사 및 PR 스태킹 금지)**:
   - 본인 직무의 미머지 열린 PR(`state:open`)이 1개라도 존재하는 경우, **신규 티켓 착수 및 `gh issue create`를 전면 금지**한다.
   - 선행 PR이 머지되기 전에 후속 작업을 브랜치로 쌓는 행위(PR Stacking)를 엄격히 금지한다.
2. **1단계 (main 최신화)**: `git checkout main && git pull origin main`으로 최신 커밋 동기화.
3. **2단계 (GitHub Issue 선발행)**:
   - `node scripts/get_my_tasks.js` 실행 (열린 PR 존재 시 하드 가드로 실행 차단됨).
   - `gh issue create --title "<타입>(<직무>): <제목>" --body "- Notion Task: <노션URL>\n- 브랜치: feat/<직무>-<기능명>"` 실행하여 이슈 번호 확보.
4. **3단계 (작업 브랜치 분기)**: `git checkout -b feat/<직무>-<기능명>` 생성 후 개발 착수.
5. **4단계 (로컬 통합 검증)**: PR 생성 전 `powershell .\scripts\check.ps1` 단일 게이트 100% 통과 (우회 플래그 사용 절대 금지).
6. **5단계 (PR 발행 및 1:1 짝꿍 리뷰어 지정)**: `gh pr create --reviewer "<짝꿍ID>"`로 PR 생성 및 상호 리뷰 요청.

### 4.2 PR 리뷰 피드백 반영 원칙 (In-PR 수정 및 이슈 증식 금지)
1. **새 이슈 생성 절대 금지 (In-PR Fix)**:
   - PR 리뷰에서 들어온 수정 요청(버그 수정, 로직 보완, 테스트 추가, 네이밍 변경)을 반영할 때 **절대로 새 GitHub Issue를 열지 않는다.**
   - 동일 PR의 작업 브랜치에서 추가 커밋(`fix(<직무>): ...`, `test(<직무>): ...`)을 작성하고 `git push`하여 기존 PR을 갱신한다.
2. **후속 이슈(Follow-up Issue) 분리 예외**:
   - 지적사항이 현재 PR의 스코프를 완전히 벗어나 타 직무(인프라/오케스트레이터 등)의 아키텍처 변경을 수반하는 경우에 한해, 테크 리드와 협의 후 별도 마일스톤의 Follow-up Issue로 1건만 분리 등록한다.


### 4.3 직무별 1:1 상호 짝꿍 리뷰어 매핑
PR 작성자는 본인 직무의 1:1 짝꿍 리뷰어를 반드시 PR 리뷰어로 지정한다:
| PR 발행 직무 (작성자) | 필수 1차 리뷰어 (GitHub ID) | 리뷰 검증 관점 |
| :--- | :--- | :--- |
| **네트워크** (`@RockCandy444`) | **보안** (`@gkacksdnjs22-stack`) | 공격 스크립트가 보안 룰 탐지 조건에 부합하는지 검증 |
| **보안** (`@gkacksdnjs22-stack`) | **클라우드 B** (`@wkdtlgns99-cell`) | 탐지 정규식이 수집 대상 로그 포맷과 일치하는지 검증 |
| **클라우드 B** (`@wkdtlgns99-cell`) | **네트워크** (`@RockCandy444`) | 타깃 EC2 포트/Nginx 설정이 모의 공격 트래픽을 수용하는지 검증 |
- 테크 리드(`@mmmphyun`)는 전역 아키텍처 및 파이프라인 거버넌스 스팟 체크를 전담한다.

### 4.4 초경량 에이전트 코드 리뷰 표준 가이드
에이전트를 활용해 PR 리뷰를 작성할 때 장황한 줄글과 사소한 트집(Nit-pick)을 금지하며 다음 규칙을 강제한다:
1. **서식 최소화**: 복잡한 헤딩/체크박스를 배제하고 단순 불릿 포인트로 작성.
2. **2단계 태그 분류**:
   - `[P1 - 필수]`: 머지 블로커 (결함, 인터페이스 불일치, CI 실패, R&R 침범).
   - `[P2 - 권장]`: 선택적 개선 사항 (성능 참고, 네이밍 제안).
3. **지적 개수 상한**: P1/P2 합산 최대 2~3개 이내로 제한.
4. **승인 기준**: P1 항목이 없으면 즉시 GitHub `Approve`를 부여.

### 4.5 커밋 메시지 컨벤션
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
1. **네트워크 (`network/`, `tests/unit/test_network.py`)**:
   - 모의 공격 셸 스크립트 작성 시 비정상 종료 방지 및 안전성 플래그(`set -euo pipefail`) 필수 적용.
   - 공격 시뮬레이션 검증 단위 테스트는 pytest 표준 수집 경로인 `tests/unit/test_network.py`에 작성.
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

- 신규 기능 구현 또는 버그 수정 시 반드시 `tests/unit/` 디렉토리에 `pytest` 테스트 코드를 함께 작성한다.
- 작업 완료 및 PR 제출 전 다음 단일 검증 스크립트를 반드시 100% 통과해야 한다:
  ```powershell
  powershell .\scripts\check.ps1
  ```
  (내부적으로 테스트 파일 경로 검증, `ruff check`, `ruff format --check`, `pytest`를 일괄 수행하며, `--no-respect-gitignore` 등 우회 플래그 사용은 엄격히 금지된다.)
- 테스트를 통과시키기 위해 기존 검증 로직이나 제약조건을 임의 삭제하는 행위를 엄격히 금지한다.

---

## 7. 안전 및 보안 규칙

1. `main` 브랜치에 직접 push하지 않는다.
2. AWS Access Key, Secret Key, API 토큰 등 자격증명을 절대 하드코딩하거나 커밋하지 않는다.
3. 실제 인프라 변경 코드는 사전 승인된 영향 범위(단일 테스트 VPC/계정) 내로 제한한다.
4. 로컬 개발 및 테스트 시에는 `moto` 기반의 가상 Mock 환경을 우선 활용한다.
