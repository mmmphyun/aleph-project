# ADR 0008: 결정론적 R&R 스코프 하드가드 구축 및 로컬 Python 단일 런타임 통일

- **상태**: 승인됨 (Accepted)
- **결정자**: 클라우드 A (테크 리드 @mmmphyun)
- **일자**: 2026-09-17
- **소유 직무**: 클라우드 A (플랫폼 거버넌스 및 CI/CD)
- **관련 PR / Issue**: PR #45, PR #63 (본 작업)

---

## 1. 배경 및 문제 제기 (Context)

1. **R&R 경계선 침범 사고 (PR #45)**:
   - 클라우드 B 담당자가 플랫폼 전담 영역인 `scripts/` 및 `tests/unit/test_scripts.py`를 임의 추가·수정하여 PR을 제출하고 머지시킴.
   - 프로젝트 헌법(`AGENTS.md`)에 직무별 R&R 경계선이 명시되어 있었으나, CI 및 로컬 게이트에 파일 변경 권한을 검증하는 물리적 하드가드가 없어 침범을 적발하지 못함.
2. **리뷰어 병목 방지 로직과 CODEOWNERS 간의 충돌**:
   - 테크 리드의 리뷰 병목을 방지하기 위해 구축된 `auto_assign_reviewer.yml`이 짝꿍 외 모든 리뷰어를 강제 삭제(Prune)함에 따라, GitHub CODEOWNERS가 지정한 코드오너 결재가 우회됨.
3. **로컬 런타임 파편화 (Node.js 강제)**:
   - 초기 하네스 구축 시 GitHub Actions 러너 환경의 편의를 위해 `scripts/get_my_tasks.js` 등 보조 도구가 Node.js로 작성됨.
   - 팀원들의 로컬 환경에 Node.js가 없어 스크립트를 실행하지 못하자, Python으로 중복 구현하는 과정에서 플랫폼 영역을 침범하게 됨.

---

## 2. 대안 검토 및 트레이드오프 분석 (Considered Options)

| 구분 | 방안 1: 소프트 가드 강화 | 방안 2: 테크 리드 필수 결재 부활 | 방안 3: 결정론적 하드가드 + Python 단일화 (채택) |
| :--- | :--- | :--- | :--- |
| **구조** | 프롬프트와 문서만 보강 | 모든 PR에 테크 리드 Approve 의무화 | CI/로컬 스코프 하드가드 구축 + 도구 Python 통일 |
| **장점** | 개발 비용 없음 | 확실한 수동 통제 가능 | **리뷰어 병목 없음 + 기계적 100% 차단 + 런타임 단순화** |
| **단점** | 재발 방어 불가 (에이전트 무시) | **테크 리드 리뷰 병목 재발로 개발 속도 저하** | 스코프 검증 엔진 개발 및 포팅 공수 소요 |

---

## 3. 아키텍처 결정 (Decision)

1. **결정론적 R&R 스코프 하드가드 엔진 구축 (`scripts/verify_rnr_scope.py`)**:
   - **CI 직무 강제**: 브랜치명이 아닌 GitHub PR 작성자 계정(`github.event.pull_request.user.login`)을 기반으로 직무를 판별.
   - **역할 사칭(Spoofing) 차단**: 타 직무 담당자가 브랜치명을 `feat/cloud-a-...` 등으로 명명하여 플랫폼 권한을 획득하려는 시도를 교차 검증하여 즉시 차단.
   - **Fail-Closed 원칙**: 미등록 계정 또는 직무 식별 불가 시 `exit 1`로 빌드 중단.
   - **정밀 Git Diff**: `git merge-base HEAD origin/main`을 사용하여 로컬 stale ref 오탐을 방지하고, Staged 및 미추적(`??`) 파일까지 검증.
2. **로컬 런타임의 Python 3.12 + `uv` 100% 단일화**:
   - 기존 `scripts/*.js` 및 `tests/unit/*.js`를 파이썬 표준 라이브러리(`urllib.request`, `json`) 기반 제로 디펜던시로 전면 포팅.
   - 팀원 로컬 개발 환경에서 Node.js 설치 종속성을 완전히 제거 (사전 필수 도구를 `uv`와 `gh` 2개로 단순화).
3. **리뷰어 Prune 로직 유지 및 CI 상태 체크 연동**:
   - `auto_assign_reviewer.yml`의 1:1 짝꿍 전담 배정 로직을 보존하여 리뷰 병목을 방지하고, 위반 파일 차단 책임은 CI의 `Verify R&R Scope Boundary` 단계가 100% 전담.

---

## 4. 결과 및 영향 (Consequences)

- **긍정적 영향**:
  - 타 직무 작업자나 코딩 에이전트가 플랫폼 및 타 포트폴리오 영역을 침범하는 것이 시스템 레벨에서 물리적으로 불가능해짐.
  - 팀원 온보딩 시 Python/uv만 설치하면 모든 도구가 즉시 동작하여 환경 설정 마찰 제거.
  - `powershell .\scripts\check.ps1` 단일 게이트에 모든 도구의 단위 테스트가 통합되어 회귀 검증 신뢰도 대폭 향상.
- **관리적 영향**:
  - 신규 팀원 합류 시 `scripts/verify_rnr_scope.py`의 `CI_ACTOR_MAP`에 GitHub 계정 등록이 필요함.
