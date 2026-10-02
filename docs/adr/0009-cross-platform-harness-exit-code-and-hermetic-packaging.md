# ADR 0009: 크로스 플랫폼 하네스 종료 코드 보장 및 밀폐 패키징 Fail-Closed 아키텍처

- **상태**: 승인됨 (Accepted)
- **결정자**: 클라우드 A (테크 리드 @mmmphyun)
- **일자**: 2026-10-02
- **소유 직무**: 클라우드 A (플랫폼 거버넌스 및 CI/CD)
- **관련 PR / Issue**: Issue #128, PR #129, Issue #130

---

## 1. 배경 및 문제 제기 (Context)

1. **PowerShell 프로세스 종료 시그널 비트랩 및 로컬 게이트 False-Positive (PR #127 제보)**:
   - 팀원 로컬 Windows 환경에서 `powershell .\scripts\check.ps1` 실행 시, Pytest에서 단위 테스트 1건이 실패했음에도 불구하고 `[성공]` 문구를 출력하고 프로세스 종료 코드 `0`을 반환하는 결함이 발생함.
   - 원인: POSIX Bash는 `set -e`로 비정상 종료 코드를 즉시 트랩하지만, Windows PowerShell은 `$ErrorActionPreference = "Stop"`이 선언되어 있어도 외부 PE 네이티브 바이너리(`ruff.exe`, `pytest.exe`)의 비정상 종료(exit code 1)를 파워셸 런타임 예외로 전환하지 않고 스크립트를 계속 진행함.
2. **Lambda 패키징 빌더의 툴체인 역추적(Backtracking) 및 검증 단계 엇갈림**:
   - AWS Lambda 런타임 배포 아티팩트 빌더(`scripts/package_lambda.py`)는 무효 플랫폼 타깃 지정 시 2단계(의존성 수집)에서 즉시 중단(`[빌드 실패] ... 호환 패키지 다운로드에 실패했습니다`)되어야 함.
   - 그러나 2순위 `pip` fallback 호출 시 버전 제약 없이 `"pydantic"`으로 호출함에 따라, `pip` 의존성 해결사가 C-Extension(`pydantic-core`)이 없는 과거의 순수 파이썬 휠(`pydantic 1.10.26`)로 역추적(Backtracking)하여 다운로드를 성공 처리함.
   - 이로 인해 2단계가 우회되고 3단계(네이티브 바이너리 검증)에서 `[빌드 차단] ... pydantic_core .so 공유 라이브러리가 번들에 누락되었습니다`로 늦게 실패하여, 테스트 정규식 불일치(`AssertionError: Regex pattern did not match`)가 유발됨.

---

## 2. 대안 검토 및 트레이드오프 분석 (Considered Options)

| 구분 | 방안 1: 테스트 정규식 완화 (임시 땜질) | 방안 2: Docker 컨테이너 빌드 강제 | 방안 3: $LASTEXITCODE 전수 가드 + Pydantic v2 고정 + 메타 테스트 (채택) |
| :--- | :--- | :--- | :--- |
| **구조** | 3단계 차단 메시지도 정규식에 허용 | Docker 데몬 기반 크로스 컴파일 | 스크립트 전 단계 종료 코드 강제 + 빌더 v2 제약 + 하네스 메타 테스트 |
| **장점** | 코드 변경 최소화 | 완전한 OS 격리 보장 | **도커 종속성 제거 + 로컬/CI 종료 코드 100% 일치 + 재현성 확보** |
| **단점** | Pydantic 1.x 잘못 탑재되는 위험 방치 | 팀원 로컬에 Docker 설치 필수, 속도 저하 | 하네스 스크립트 및 테스트 작성 공수 발생 |

---

## 3. 아키텍처 결정 (Decision)

1. **PowerShell 검증 게이트의 `$LASTEXITCODE` 명시적 조기 종료(Fail-Closed)**:
   - `scripts/check.ps1`의 모든 검증 단계([0/5] R&R, [2/5] Lint, [3/5] Format, [4/5] Pytest) 실행 직후 `if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }` 가드를 전수 배치.
   - 외부 프로세스 실행 실패 시 후속 단계 실행을 물리적으로 차단하고 호출 프로세스에 실패 종료 코드를 즉시 전파.
2. **하네스 무결성 검증을 위한 메타 테스트(Meta-Test) 도입**:
   - `tests/unit/test_scripts.py::test_check_ps1_contains_exit_code_guards`를 신설하여 `check.ps1` 소스 코드 내에 모든 단계별 종료 코드 가드가 존재하는지 정적 검증.
   - 향후 하네스 수정 시 가드가 누락되는 회귀를 CI 레벨에서 원천 방지.
3. **Lambda 패키징 툴체인의 Pydantic v2 제약 고정 및 코어 무결성 검증**:
   - `scripts/package_lambda.py`의 `uv` 및 `pip` 설치 패키지 명세를 `"pydantic>=2.0"`으로 엄격히 고정하여 하위 버전 역추적 다운로드 원천 차단.
   - `fetch_linux_dependencies()`의 성공 조건에 `(target_dir / "pydantic_core").exists()`를 필수 결합하여 네이티브 코어 미탑재 시 즉시 `False` 반환(2단계 조기 Fail-Closed 보장).

---

## 4. 결과 및 영향 (Consequences)

- **긍정적 영향**:
  - 팀원 로컬(Windows) 환경과 중앙 CI(Linux Ubuntu) 환경 간의 품질 검증 판정 결과가 100% 동일하게 일치됨.
  - 호스트 머신의 `pip` 설치 유무나 글로벌 패키지 오염에 영향받지 않는 결정론적 밀폐 빌드(Hermetic Build) 달성.
  - 단일 테스트 실패를 숨기고 `main`에 머지하려는 시도가 시스템 레벨에서 원천 차단됨.
- **관리적 영향**:
  - 향후 `check.ps1`에 신규 검증 도구를 추가할 경우 반드시 `$LASTEXITCODE` 가드를 삽입하고 메타 테스트를 동기화해야 함.
