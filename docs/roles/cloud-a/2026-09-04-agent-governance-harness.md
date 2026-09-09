# CloudShield 컨트랙트 퍼스트 에이전트 거버넌스 하네스 구축 보고서

> **작성일**: 2026-09-04  
> **작성자**: 클라우드 A (플랫폼 엔지니어 / 테크 리드)  
> **문서 상태**: 확정 및 동결 (Baseline Freeze)

---

## 1. 추진 배경 및 목적

- **문제 인식**: AI 코딩 에이전트(Cursor, Windsurf, Claude Code 등)를 도입할 경우, 에이전트가 타 팀원의 코드를 무단 수정하거나 사전 합의되지 않은 데이터 구조를 작성하여 런타임 통합 실패를 유발할 위험이 큼.
- **목적**:
  - 팀원들의 도메인 지분(네트워크 패킷 분석, CloudWatch 로깅/알림, 시그니처/LLM 룰)을 절대 침범하지 않는 물리적/논리적 경계 수립.
  - 실제 AWS 배포 전 로컬에서 독립 개발 및 상호 검증이 가능한 **컨트랙트 퍼스트 최소 실행 가능 하네스(MVH, Minimum Viable Harness)** 완성.

---

## 2. 하네스 핵심 아키텍처 및 구성 요소

### 2.1 인터페이스 데이터 계약 (`src/contracts/`)
- `IncidentReport` (`src/contracts/incident.py`):
  - Pydantic V2 기반 불변(`frozen=True`, `extra="forbid"`) 모델.
  - 침해사고 식별자, 출발지 IP, 타깃 EC2 인스턴스 ID, 필수 차단 액션(`action_required`), 한글 요약(`summary_ko`) 정의.
  - 파이썬 표준 라이브러리 `ipaddress.IPv4Address`를 통한 옥텟 무결성 검증.
- `CloudWatchLogsPayload` 및 `SyslogAuthEvent` (`src/contracts/events.py`):
  - 리눅스 표준 `/var/log/auth.log` 실패 이벤트 파싱 (전통 BSD 및 ISO 8601 타임스탬프 동시 지원).
  - AWS CloudWatch Logs Subscription Filter의 Gzip/Base64 압축 해제 및 역인코딩 양방향 팩토리 제공.

### 2.2 독립 개발용 Mock 데이터셋 (`tests/mock_data/`)
- `mock_auth.log`: 실제 SSH Brute Force 공격 시 발생하는 5개 라인의 원문 로그 샘플.
- `mock_cw_event.json`: CloudWatch Logs에서 Lambda로 전달되는 Base64/Gzip 인코딩된 실제 형태의 이벤트 페이로드.
- `mock_incident.json`: 보안 분석 엔진이 생성하여 차단 엔진 및 Slack 알림 모듈로 전달하는 표준 JSON 인시던트 데이터.

### 2.3 거버넌스 가드 및 에이전트 헌법
- `AGENTS.md`: 단일 소유권 매트릭스(Single Ownership Matrix) 및 4대 직무별 산출물 특화 표준 명시.
- `.agent-role`: 로컬 세션 시작 시 사용자 역할을 자동 감지하고 타 디렉토리 수정을 잠그는 소프트 가드.
- GitHub Actions 원격 가드:
  - `pr_title_lint.yml`: Conventional Commit 및 필수 직무 스코프 강제.
  - `labeler.yml`: 파일 변경 경로 기반 `role:*`, `area:*`, `type:*` 라벨 100% 자동 부착.
  - `ci.yml`: `main`, `feat/**`, `fix/**` 브랜치에 대한 Ruff Lint, Format, Pytest 자동 검증.

---

## 3. 레드팀(Red Teaming) 평가 및 최적화 반영 내역

| 점검 영역 | 초기 상태 | 결함 및 오버엔지니어링 분석 | 최종 최적화 조치 |
| :--- | :--- | :--- | :--- |
| **IP 검증** | 정규식 + `ipaddress` 2중 검사 | 정규식과 표준 라이브러리의 중복 호출로 복잡도 증가 | 정규식 제거, `ipaddress.IPv4Address` 단일 호출로 통합 (Ponytail 최적화) |
| **타임스탬프** | BSD 포맷(`Sep 03 14:20:01`)만 허용 | 최신 Ubuntu systemd/rsyslog ISO 8601 인제스트 시 무음 누락(Silent Drop) 위험 | 정규식에 ISO 8601 포맷 확장 반영 |
| **타입 안전성** | `list[str]` 선언 | `frozen=True` 모델임에도 참조 변조 가능한 mutable 타입 노출 | `tuple[str, ...]` 불변 시퀀스로 전환 |
| **CI 트리거** | `main` 및 단일 브랜치 한정 | 기능 브랜치(`feat/*`, `fix/*`) PR 오픈 시 CI 미동작 위험 | 브랜치 패턴 `[main, "feat/**", "fix/**"]`로 확장 |
| **로컬 가드** | Git pre-commit 강제 검토 | AI 에이전트 탈선 및 비전공자 로컬 실행 환경(PowerShell 등) 충돌 위험 | 로컬 훅 강제 배제, PR CI 단일 창구 집중 전략 채택 |
| **브랜치 보호** | Classic + Ruleset 이중 적용 | GitHub Most Restrictive 정책으로 리드 1인 오너 승인 병목 발생 | Classic 완전 삭제, Ruleset 단일화 및 1:1 상호 짝꿍 리뷰 체계 전환 (ADR-0005) |
| **거버넌스 가드** | 헌법/문서 기반 소프트 가드 | 에이전트의 노션 링크 누락, 이슈 미생성, tests 경로 이탈 반복 | PR 메타데이터 CI 검증 및 테스트 경로 정적 검증 하드 가드 이원화 (ADR-0006) |
| **실행 안정성** | `uv run pytest` 바이너리 호출 | Windows AppLocker/보안 정책 환경에서 바이너리 차단(os error 4551) | `scripts/check.ps1`을 `python -m pytest` 호출로 표준화하여 호환성 확보 |

---

## 4. 하네스 동결(Freeze) 및 차기 플랫폼 공정

- **하네스 베이스라인 동결**:
  - 추가적인 가상 엣지케이스 선제 방어 작업을 즉시 중단하고 현재 커밋 상태로 하네스 동결.
  - 향후 인터페이스 수정은 팀원 개발 중 발생하는 실제 이슈 기반(Bug-driven)으로만 PR을 통해 점진적 수정.
- **차기 공정 (Day 2 플랫폼 엔지니어링 착수)**:
  1. `pyproject.toml`에 `boto3`, `moto[ec2,wafv2,iam]` 의존성 추가.
  2. `tests/conftest.py`에 Moto 가상 AWS 리소스 픽스처 구축.
  3. `src/remediation/remediation.py` 다중 계층(L4 SG 격리 / L7 WAF IPSet / IAM 세션 무효화) 원자적 복합 차단 엔진 구현.
