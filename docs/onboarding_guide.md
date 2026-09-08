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

## 3. 직무별 작업 영역 및 표준 프롬프트

각 담당자는 본인에게 할당된 작업 디렉토리 내에서 개발을 진행합니다. 작업 착수 시 사용하는 코딩 에이전트의 채팅창에 아래 **표준 프롬프트**를 복사하여 전달합니다.

### 3.1 [보안 담당자]
* **작업 디렉토리**: `src/detection/`, `tests/unit/test_rules.py`, `tests/unit/test_llm_analyzer.py`
* **표준 프롬프트**:
  ```text
  나는 CloudShield 프로젝트의 [보안] 담당자야.
  AGENTS.md와 docs/05_security_workflow.md를 확인해줘.
  tests/mock_data/mock_auth.log를 기반으로 SSH 무차별 대입 공격을 탐지하는 
  1차 시그니처 정규식 룰(src/detection/rules.py)을 구현하고, 
  tests/unit/test_rules.py의 테스트를 통과시키는 코드를 작성해줘.
  ```

### 3.2 [클라우드 B 담당자]
* **작업 디렉토리**: `src/collector/`, `src/reporter/`, `tests/unit/test_reporter.py`
* **표준 프롬프트**:
  ```text
  나는 CloudShield 프로젝트의 [클라우드 B] 담당자야.
  AGENTS.md와 docs/04_cloud_b_workflow.md를 확인해줘.
  tests/mock_data/mock_incident.json 데이터를 입력받아 
  Slack Block Kit 카드 메시지를 구성하고 발송하는 모듈(src/reporter/slack_notifier.py)을 구현하고,
  tests/unit/test_reporter.py의 단위 테스트를 작성해줘.
  ```

### 3.3 [네트워크 담당자]
* **작업 디렉토리**: `network/`, `docs/roles/network/`
* **표준 프롬프트**:
  ```text
  나는 CloudShield 프로젝트의 [네트워크] 담당자야.
  AGENTS.md와 docs/02_network_workflow.md를 확인해줘.
  타깃 서버 대상 SSH Brute Force 공격 시뮬레이션 스크립트(network/attack_simulation.sh)를 
  안전성 플래그(set -euo pipefail)를 적용해 작성해줘.
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

---

## 5. 풀 리퀘스트(PR) 제출 전 필수 로컬 검증

PR을 생성하기 전, 로컬 터미널에서 다음 3대 검증 명령어를 반드시 통과해야 합니다. 이 중 하나라도 실패하면 GitHub CI에서 머지가 자동 차단됩니다.

```powershell
# 1. 코드 스타일 및 린트 검사
uv run ruff check .

# 2. 코드 포맷팅 검사
uv run ruff format --check .

# 3. 전체 단위 테스트 실행
uv run pytest
```

---

## 6. PR 작성 및 노션 자동 연동

1. GitHub 저장소에서 `main` 브랜치를 대상으로 PR을 생성합니다.
2. PR 템플릿에 맞춰 아래 항목을 작성합니다:
   * 관련 노션 카드 링크 및 이슈 번호.
   * **기술 원리 3줄 요약 (필수)**: 에이전트가 작성한 코드의 핵심 로직과 동작 원리를 담당자가 직접 기술합니다.
3. PR이 머지되면 GitHub Actions가 노션 칸반 보드의 카드 상태를 자동으로 `완료`로 변경하고, 작성한 3줄 요약을 성과 기록으로 자동 동기화합니다.
