# CloudShield 플랫폼 하네스 진화 및 6대 결함 심층 포스트모템 (SecOps Harness Evolution & Postmortem)

- **작성자**: 클라우드 A (테크 리드 @mmmphyun)
- **일자**: 2026-10-02
- **대상 독자**: 플랫폼 엔지니어링 팀, DevSecOps 기술 면접관

---

## 1. 개요 및 하네스 거버넌스 철학

CloudShield는 단일 10초 관통 위협 자동 대응 파이프라인(L4 SG / L7 WAF / IAM 세션 차단)을 목표로 하는 고속 협업 프로젝트이다. 4인의 직무(네트워크, 클라우드 B, 보안, 클라우드 A)가 병렬로 기능을 개발함에 따라, **"사람의 주의력이나 구두 합의에 의존하지 않고, 물리적 하네스(코드와 CI 게이트)로 무결성을 기계적으로 강제한다(Harness-First)"**는 원칙을 채택하였다.

본 문서는 프로젝트 개발 과정에서 팀원들의 피드백과 교차 검증을 통해 발견되고 테크 리드 핫픽스로 신속히 격리·진화된 **6대 하네스 결함의 근본 원인(Root Cause), 해결 아키텍처, 그리고 면접용 기술적 방어 논리**를 집대성한다.

---

## 2. 6대 하네스 결함 포스트모템 매트릭스

| 번호 | 관련 PR | 결함 유형 | 발생 원인 (Root Cause) | 해결 조치 및 하드가드 구축 |
| :---: | :---: | :---: | :--- | :--- |
| **01** | PR #64, #66 | **R&R 스코프 침범** | 직무별 허용 파일 경계선 검증 부재로 타 직무가 플랫폼 코드를 임의 수정함 | `scripts/verify_rnr_scope.py` 하드가드 구축, PR 작성자 GitHub ID 기반 화이트리스트 강제 |
| **02** | PR #81 | **외부 연동 파싱 결함** | Notion Task URL 내 불규칙한 쿼리 파라미터(`?p=...`)로 인해 정규식 카드 ID 추출 실패 | 정규식 패턴 세분화 및 URL 디코딩 정규화 테스트 슈트 구축 |
| **03** | PR #88 | **CLI 스트림 인코딩 결함** | PowerShell 파이프라인의 기본 인코딩(ANSI/EUC-KR)으로 인해 노션 동기화 시 UTF-8 한글이 깨지고 카드 제목이 유실됨 | Node.js 완전 퇴출, Python `urllib` 기반 제로 디펜던시 포팅 및 UTF-8 스트림 강제 |
| **04** | PR #100 | **시크릿 누출 및 AI 아티팩트 오탐** | `.env` 등 시크릿 파일이 Staged 인덱스에 포함되어도 감지하지 못하고, AI 도구 임시 폴더가 R&R 검증을 차단함 | Git Staged/Committed 인덱스 정밀 검사(`check_forbidden_secrets`) 및 AI 도구 경로 예외 분리 |
| **05** | PR #112 | **인터페이스 계약 불일치** | 중앙 `IncidentReport` 스키마 변경 시 타 직무의 모의 데이터셋(`tests/mock_data/`)이 비동기화되어 회귀 유발 | `test_contracts.py` 계약 불변성 검증 하드가드 신설 및 역직렬화 체인 전수 동기화 |
| **06** | PR #129, #130 | **종료 코드 은폐 및 Hermetic Build 결함** | PowerShell 네이티브 바이너리 비트랩으로 테스트 실패 시 0 반환 + pip의 Pydantic v1.x 역추적 다운로드 버그 | `check.ps1` 전 단계 `$LASTEXITCODE` 가드, 하네스 메타 테스트, `pydantic>=2.0` 제약 고정 |

---

## 3. 심층 기술 메커니즘 분석 (CS & OS 계층별 접근)

### 3.1 OS 인터프리터 계층: Windows PE 네이티브 바이너리 vs POSIX Shell 시그널 전파
* **현상**: `scripts/check.ps1`에서 Pytest 1건이 실패했음에도 스크립트가 중단되지 않고 `[성공]`을 출력함.
* **원리**: 
  - Linux POSIX Shell은 `set -e`가 활성화되면 서브프로세스가 0이 아닌 종료 코드를 반환할 때 즉시 셸 인터프리터가 `SIGCHLD`를 감지하고 조기 종료함.
  - 반면 Windows PowerShell은 `$ErrorActionPreference = "Stop"`을 지정하더라도 PowerShell 내부 cmdlet의 예외만 트랩하며, 외부 PE 포맷의 네이티브 프로세스(`pytest.exe`, `ruff.exe`)가 반환한 종료 코드는 무시함.
* **해결**: 모든 외부 프로세스 호출 직후 전역 환경 변수 `$LASTEXITCODE`를 명시적으로 평가하여 조기 `exit $LASTEXITCODE`를 강제하고, 이 가드가 누락되지 않도록 AST/정적 파싱 기반 메타 테스트(`test_check_ps1_contains_exit_code_guards`)를 신설함.

### 3.2 패키지 매니저 계층: uv vs pip 의존성 해결 알고리즘(Backtracking)의 함정
* **현상**: Lambda 배포용 Linux 휠 빌더에 지원되지 않는 가상 플랫폼(`invalid-non-existent-platform`)을 넘겼음에도 불구하고 빌드가 성공하거나 엉뚱한 에러가 발생함.
* **원리**:
  - `uv`는 플랫폼 태그 유효성을 사전에 검증하여 즉시 차단함.
  - 그러나 2순위 fallback으로 사용된 표준 `pip`은 컴파일된 C-Extension(`pydantic-core`) 휠을 찾지 못하자 하위 버전을 역추적(Backtracking)함.
  - C-Extension이 도입되기 전인 과거의 순수 파이썬 휠(`pydantic 1.10.26-py3-none-any.whl`)이 모든 플랫폼(`none-any`)과 호환된다고 판단하여 다운로드를 성공 처리함.
  - 이로 인해 의존성 수집 단계는 통과하고, 후속 바이너리 검증 단계에서 `.so` 누락 예외로 늦게 실패하여 정규식 불일치가 유발됨.
* **해결**: 설치 인자에 `"pydantic>=2.0"` 명세를 강제하여 v1.x 역추적을 수학적으로 차단하고, `pydantic_core` 디렉터리 존재 여부를 물리적으로 검증하여 밀폐 빌드(Hermetic Build) 무결성을 완성함.

---

## 4. 플랫폼 엔지니어링 교훈 및 아키텍처 재발 방지 원칙 (Engineering Lessons & Prevention Principles)

### 4.1 크로스 플랫폼 셸 스크립팅 및 시그널 전파 원칙
1. **프로세스 종료 코드($LASTEXITCODE) 명시적 트랩**:
   - OS 및 셸 런타임(Windows PowerShell vs Linux Bash)에 따라 에러 액션 전파 메커니즘이 근본적으로 상이함을 인지하고, 모든 외부 프로세스 실행 후에는 환경 설정(`$ErrorActionPreference`)에 의존하지 않고 명시적으로 `$LASTEXITCODE`를 평가하여 조기 중단(Fail-Closed)해야 함.
2. **하네스 자체에 대한 메타 테스트(Meta-Test) 의무화**:
   - 검증 스크립트(`check.ps1`) 자체의 가드 누락은 시스템 전체의 신뢰성을 무너뜨리는 단일 실패점(SPOF)이 되므로, 정적 분석 단위 테스트(`test_check_ps1_contains_exit_code_guards`)를 통해 하네스 코드의 불변성을 상시 검증해야 함.

### 4.2 다중 툴체인 런타임 패키징 및 의존성 격리 원칙
1. **상위 의존성 제약 고정 (Strict Version Constraints)**:
   - 복합 패키지 매니저(`uv`, `pip`)를 혼용하는 fallback 체인에서는 하위 호환성 역추적(Backtracking) 알고리즘으로 인해 구버전 순수 파이썬 패키지가 잘못 유입될 수 있으므로, 최소 메이저/마이너 버전 제약(`pydantic>=2.0`)을 설치 인자에 명시적으로 고정해야 함.
2. **결정론적 아티팩트 산출물 직접 검증 (Post-Install Artifact Assertion)**:
   - 패키지 매니저의 프로세스 종료 코드(0)에만 의존하지 않고, 런타임에 필수적인 네이티브 바이너리 디렉터리(`pydantic_core`)의 실존 여부를 파일시스템 레벨에서 직접 검증한 후 다음 빌드 단계로 이행해야 함.

### 4.3 R&R 기반 자율 주행 하네스 및 Fail-Closed 거버넌스 원칙
1. **단일 소유권 원칙(Single Ownership) 엄수**:
   - 플랫폼 하네스 및 공통 스크립트는 클라우드 A의 단독 소유 자산으로, 타 직무에서 결함이 관측되더라도 임의 수정 대신 정식 보고 및 테크 리드 Fast-Track 핫픽스를 통해 통제된 변경을 수행함.
2. **다중 방어선(Defense-in-Depth) 구조 유지**:
   - 로컬 검증 게이트(`check.ps1`) $\rightarrow$ 동료 간 1:1 코드 리뷰 $\rightarrow$ 중앙 CI 워크플로우(`.github/workflows/ci.yml`)로 이어지는 3단계 독립 방어선을 유지하여 단일 계층 결함이 프로덕션/메인 브랜치로 누출되는 것을 차단함.

