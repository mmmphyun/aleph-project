# CloudShield: 팀원 온보딩 퀵스타트 가이드

본 문서는 CloudShield 프로젝트에 참여하는 각 분야 담당자가 로컬 개발 환경을 설정하고, 코딩 에이전트를 활용하여 안전하게 개발에 참여할 수 있도록 돕는 표준 안내서입니다.

---

## 1. 사전 준비 및 로컬 환경 설정 (1분 셋업)

### 1.1 저장소 복제 및 의존성 동기화
터미널(PowerShell 또는 Bash)에서 아래 명령어를 순차적으로 실행합니다:

```powershell
# 1. 저장소 클론 및 이동
git clone https://github.com/mmmphyun/aleph-project.git
cd aleph-project

# 2. uv 패키지 매니저를 통한 가상환경 동기화 (Python 3.12+ 자동 세팅)
uv sync
```

---

## 2. 역할 잠금 설정 (`.agent-role`)

코딩 에이전트(Cursor, Claude Code, Antigravity 등)가 본인의 담당 직무 영역 외의 파일을 임의로 수정하지 못하도록 프로젝트 루트에 `.agent-role` 파일을 생성합니다.

### 직무별 설정 명령어 (택 1 실행)

* **네트워크 담당자**:
  ```powershell
  Set-Content -Path .agent-role -Value "network" -NoNewline
  ```
* **클라우드 B 담당자**:
  ```powershell
  Set-Content -Path .agent-role -Value "cloud-b" -NoNewline
  ```
* **보안 담당자**:
  ```powershell
  Set-Content -Path .agent-role -Value "security" -NoNewline
  ```

> **주의**: `.agent-role` 파일은 `.gitignore`에 등록되어 원격 저장소에 커밋되지 않으므로 각자의 로컬에서 1회만 설정하면 됩니다.

---

## 2.1 작업 착수 전 티켓 확인 및 GitHub Issue 생성

새 작업을 시작할 때 노션 [프로젝트 일정] DB의 티켓을 확인하고 GitHub Issue를 먼저 생성합니다:

1. **자동 조회 (`node scripts/get_my_tasks.js`)**:
   - `.env`에 `NOTION_API_KEY`가 설정된 경우 본인 직무의 `[시작 전]` 티켓 목록과 링크가 콘솔에 자동 출력됩니다.
2. **수동 연동 (Fallback - API 키 미설정 시)**:
   - 노션 웹 칸반 보드에서 본인 일감 카드의 링크를 복사한 뒤, GitHub CLI로 이슈를 생성합니다:
     ```powershell
     gh issue create --title "feat(<직무>): <작업_제목>" --body "- Notion Task: <복사한_노션_카드_URL>`n- 브랜치: feat/<직무>-<기능명>"
     ```
   - 또는 GitHub 웹 저장소의 **Issues $\rightarrow$ New issue**를 통해 수동 등록합니다.

---

## 3. 직무별 작업 영역 및 표준 프롬프트

각 담당자는 본인에게 할당된 작업 디렉토리 내에서 개발을 진행합니다. 작업 착수 시 사용하는 코딩 에이전트의 채팅창에 아래 **표준 프롬프트**를 복사하여 전달합니다.

### 3.1 [보안 담당자 - 1단계 일감 프롬프트]
* **작업 티켓**: `[보안] mock_auth.log 공격자 IP 및 계정 추출 정규식 작성`
* **작업 디렉토리**: `src/detection/`, `tests/unit/test_rules.py`
* **표준 프롬프트**:
  ```text
  나는 CloudShield 프로젝트의 [보안] 담당자야.
  AGENTS.md를 확인하고, 작업 착수 전 반드시 다음 사전 절차를 먼저 확인해줘:
  1. git checkout main && git pull origin main 으로 최신 상태 동기화
  2. 노션 카드 URL을 확인하고 gh issue create 로 사전 이슈 번호 확보
  3. git checkout -b feat/security-rules-engine 브랜치 생성

  이번 작업 범위는 1단계 마이크로 티켓이야:
  [목표]: tests/mock_data/mock_auth.log 원문에서 공격자 IP와 대상 계정을 추출하는 
  1차 정규식 파싱 함수(src/detection/rules.py)를 구현하고 단위 테스트(tests/unit/test_rules.py)를 작성해줘.
  
  주의:
  1. ReDoS(Catastrophic Backtracking)를 방어하는 안전한 정규식으로 설계해줘.
  2. 다음 단계인 '실패 카운팅'이나 'IncidentReport 연동'은 지금 구현하지 마.
  3. 코딩 전 핵심 정규식 패턴과 설계 원리를 2~3줄로 먼저 설명해줘.
  4. 작업 완료 후 반드시 powershell .\scripts\check.ps1 을 실행해 100% 통과를 검증해줘.
  ```

### 3.2 [클라우드 B 담당자 - 1단계 일감 프롬프트]
* **작업 티켓**: `[클라우드 B] amazon-cloudwatch-agent.json 로그 수집 설정 및 JSON 검증`
* **작업 디렉토리**: `src/collector/`, `tests/unit/test_collector.py`
* **표준 프롬프트**:
  ```text
  나는 CloudShield 프로젝트의 [클라우드 B] 담당자야.
  AGENTS.md를 확인하고, 작업 착수 전 반드시 다음 사전 절차를 먼저 확인해줘:
  1. git checkout main && git pull origin main 으로 최신 상태 동기화
  2. 노션 카드 URL을 확인하고 gh issue create 로 사전 이슈 번호 확보
  3. git checkout -b feat/cloud-b-cw-agent-config 브랜치 생성

  이번 작업 범위는 1단계 마이크로 티켓이야:
  [목표]: 타깃 EC2의 /var/log/auth.log를 CloudWatch Logs로 전송하기 위한
  amazon-cloudwatch-agent.json 설정 명세서를 src/collector/ 디렉토리에 작성해줘.
  
  주의:
  1. JSON 문법 유효성과 로그 그룹명(/cloudshield/target/auth-log)을 준수해줘.
  2. 코딩 전 CloudWatch Agent 수집 주기 및 버퍼 설정 원리를 2~3줄로 먼저 설명해줘.
  3. 작업 완료 후 반드시 powershell .\scripts\check.ps1 을 실행해 100% 통과를 검증해줘.
  ```

### 3.3 [네트워크 담당자 - 1단계 일감 프롬프트]
* **작업 티켓**: `[네트워크] SSH 단일 연결 시도 셸 스크립트 및 안전 플래그(set -euo) 작성`
* **작업 디렉토리**: `network/`, `tests/unit/test_network.py`
* **표준 프롬프트**:
  ```text
  나는 CloudShield 프로젝트의 [네트워크] 담당자야.
  AGENTS.md를 확인하고, 작업 착수 전 반드시 다음 사전 절차를 먼저 확인해줘:
  1. git checkout main && git pull origin main 으로 최신 상태 동기화
  2. 노션 카드 URL을 확인하고 gh issue create 로 사전 이슈 번호 확보
  3. git checkout -b feat/network-ssh-bruteforce 브랜치 생성

  이번 작업 범위는 1단계 마이크로 티켓이야:
  [목표]: 타깃 서버 대상 SSH 연결 시도를 수행하는 기초 셸 스크립트(network/attack_simulation.sh)를 작성해줘.
  
  주의:
  1. 스크립트 상단에 안전성 플래그(set -euo pipefail)를 반드시 적용해줘.
  2. 다음 단계인 'Hydra 무차별 대입'이나 'tcpdump 패킷 캡처'는 지금 구현하지 마.
  3. 테스트 코드는 network/tests 가 아닌 tests/unit/test_network.py 에 작성해줘.
  4. 작성 전 set -euo pipefail 플래그를 쓰는 이유를 2~3줄로 먼저 설명해줘.
  5. 작업 완료 후 반드시 powershell .\scripts\check.ps1 을 실행해 100% 통과를 검증해줘.
  ```

---

## 4. Git 브랜치 및 커밋 규칙

### 4.1 작업 브랜치 생성
작업 시작 전 항상 최신 `main` 브랜치에서 기능 브랜치를 분기합니다:

```powershell
git checkout main
git pull origin main
git checkout -b feat/<직무명>-<기능명>
# 예: git checkout -b feat/security-rules-engine
# 예: git checkout -b feat/cloud-b-slack-card
```

### 4.2 커밋 메시지 컨벤션
* **형식**: `<type>(<scope>): <한글 요약>` (마침표 없음)
* **Scope 규격**: `network`, `cloud-b`, `security`
* **예시**:
  * `feat(security): SSH 단일 계정 무차별 대입 1차 탐지 룰 구현`
  * `feat(cloud-b): Slack Block Kit 침해사고 알림 카드 템플릿 작성`
  * `docs(network): SYN 스캔 패킷 분석 보고서 초안 작성`

### 4.3 직무별 1:1 상호 짝꿍 리뷰어 매핑 표
PR을 생성할 때는 아래 짝꿍 팀원을 리뷰어(`--reviewer`)로 반드시 지정합니다:

| PR 발행 직무 (작성자) | 필수 1차 리뷰어 (GitHub ID) | 리뷰 검증 관점 |
| :--- | :--- | :--- |
| **네트워크** (`@RockCandy444`) | **보안** (`@gkacksdnjs22-stack`) | 공격 스크립트가 보안 룰 탐지 조건에 부합하는지 검증 |
| **보안** (`@gkacksdnjs22-stack`) | **클라우드 B** (`@wkdtlgns99-cell`) | 탐지 정규식이 수집 대상 로그 포맷과 일치하는지 검증 |
| **클라우드 B** (`@wkdtlgns99-cell`) | **네트워크** (`@RockCandy444`) | 타깃 EC2 포트 및 Nginx 설정이 공격 트래픽을 수용하는지 검증 |

---

## 5. 풀 리퀘스트(PR) 제출 전 필수 로컬 검증 (단일 게이트)

PR을 생성하기 전, 로컬 터미널에서 다음 단일 검증 스크립트를 반드시 실행하여 통과해야 합니다. 이 스크립트는 코드 스타일(`ruff check`), 포맷팅(`ruff format --check`), 전체 단위 테스트(`pytest`)를 일괄 수행합니다.

```powershell
powershell .\scripts\check.ps1
```

> **주의**: `--no-respect-gitignore` 등 린트/포맷 검사를 회피하는 임의 우회 플래그 사용은 엄격히 금지됩니다. 로컬 상위 폴더의 충돌 파일이 있다면 상위 파일을 정리하고 순정 상태로 통과해야 합니다.

---

## 6. PR 작성 및 짝꿍 리뷰어 지정

1. GitHub 저장소에서 `main` 브랜치를 대상으로 PR을 생성합니다. CLI 명령어로 짝꿍 리뷰어를 지정하여 생성할 수 있습니다:
   ```powershell
   gh pr create --title "feat(<직무>): <요약>" --reviewer "<짝꿍_GitHub_ID>"
   ```
2. PR 템플릿에 맞춰 아래 항목을 작성합니다:
   * 관련 노션 카드 링크 및 사전 생성한 GitHub 이슈 번호 (`#...`).
   * **기술 원리 3줄 요약 (필수)**: 에이전트가 작성한 코드의 핵심 로직과 동작 원리를 담당자가 직접 기술합니다.
3. PR이 머지되면 GitHub Actions가 노션 칸반 보드의 카드 상태를 자동으로 `완료`로 변경하고, 작성한 3줄 요약을 성과 기록으로 자동 동기화합니다.

---

## 7. 에이전트 활용 상호 코드 리뷰 표준 가이드

팀원이 본인의 코딩 에이전트(Claude, Codex, Cursor 등)에게 동료 PR 리뷰를 요청할 때는 장황한 줄글과 불필요한 트집(Nit-pick)을 방지하기 위해 다음 규칙을 적용합니다.

### 7.1 리뷰 작성 3대 원칙
1. **서식 최소화**: 복잡한 헤딩, 표, 체크박스를 전면 배제하고 단순 불릿 포인트로 작성합니다.
2. **2단계 태그 분류**:
   - `[P1 - 필수]`: 머지 블로커 (치명적 결함, 인터페이스 위반, CI 실패, R&R 침범).
   - `[P2 - 권장]`: 선택적 개선 사항 (경미한 성능 참고, 네이밍 제안).
3. **지적 개수 상한**: P1/P2를 합산하여 최대 2~3개 이내로 제한합니다.
4. **승인 조건**: `[P1]` 항목이 없다면 GitHub 네이티브 `Approve`를 즉시 부여합니다.

### 7.2 에이전트 전달용 표준 프롬프트 문구
에이전트에게 리뷰를 요청할 때 프롬프트 끝에 다음 문장을 붙여 실행합니다:

```text
동료의 PR 코드를 검토해줘.
주의:
1. 이번 작업은 1단계 마이크로 티켓이므로 다음 단계 기능이나 과도한 최적화를 요구하지 마.
2. 장황한 설명이나 이모지, 복잡한 서식을 배제하고 핵심만 불릿 포인트로 작성해줘.
3. 치명적인 결함은 '[P1]', 사소한 권장사항은 '[P2]'로 태그를 달고, 합산 최대 2개까지만 제시해줘.
4. P1에 해당하는 중대한 결함이 없다면 사소한 트집 없이 머지 승인(Approve) 코멘트만 남겨줘.
```
