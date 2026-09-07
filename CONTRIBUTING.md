# 기여 가이드

## 기본 작업 흐름

```text
Issue 확인 또는 생성
→ 작업 브랜치 생성
→ 작은 단위로 수정·커밋
→ 로컬 검사
→ PR 생성
→ 리뷰와 CI 통과
→ main 병합
```

`main` 브랜치에 직접 Push하지 않습니다.

## 브랜치 생성

```bash
git switch main
git pull --ff-only origin main
git switch -c feat/cloud-b-slack-card
```

브랜치 이름은 GitHub Flow 및 직무 스코프 규격을 따릅니다:
- `feat/<직무>-<기능명>` (예: `feat/security-rules-engine`, `feat/cloud-a-harness`)
- `fix/<이슈명>`
- `chore/<작업명>`

## 로컬 환경 준비

Python 3.12 이상 3.15 미만 환경을 사용합니다.

팀원 온보딩 및 개발 에이전트 세팅 시에는 [팀원 온보딩 퀵스타트 가이드](docs/onboarding_guide.md) 및 [에이전트 세션 스타터](docs/agent_session_starter.md)를 먼저 확인합니다.

```powershell
# 1. uv 가상환경 동기화 (권장)
uv sync

# 또는 pip 개발 의존성 설치
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

로컬 검사 실행:

```powershell
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

## 커밋 메시지 컨벤션

커밋은 하나의 원자적 작업 단위만 포함합니다.

```text
<type>(<scope>): <한글 요약>
```

- **Type**: `feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `style`, `perf`, `ci`
- **Scope**: 담당 직무 및 핵심 도메인 (`contract`, `cloud-a`, `cloud-b`, `security`, `network`, `infra`)
- **규칙**: 한글 요약 끝에 마침표를 찍지 않습니다.

예시:

```text
feat(security): SSH 무차별 대입 1차 시그니처 룰 구현
feat(cloud-b): CloudWatch 구독 필터 연동 Slack 알림 모듈 작성
chore(cloud-a): moto 기반 가상 AWS 리소스 픽스처 추가
docs(network): Hydra 공격 시뮬레이션 패킷 분석 보고서 초안 작성
```

## Pull Request

PR을 만들 때 템플릿의 모든 항목을 작성합니다. 특히 다음 내용을 빠뜨리지 않습니다.

- 실행한 검사와 결과
- IAM 또는 AWS 리소스 변경 여부
- LLM을 사용한 범위
- 리뷰어가 확인할 부분
- 알려진 한계

리뷰어가 승인하기 전에는 PR을 직접 Merge하지 않습니다.

PR의 변경 파일 경로가 `area:cloud`, `area:iam`, `area:network`, `area:detection`, `area:response` 규칙과 일치하면 GitHub Actions가 영역 라벨을 자동으로 추가합니다. 여러 영역에 걸친 변경은 여러 라벨이 붙을 수 있으며, `priority:high`는 사람이 판단해서 직접 지정합니다. Issue의 `type:*` 라벨은 Issue 템플릿에서 기본 지정됩니다.

## LLM 사용

LLM은 코드·테스트·문서 초안 작성에 사용할 수 있습니다. 그러나 생성된 결과를 그대로 신뢰하지 않습니다.

- 작업 전 관련 문서를 읽습니다.
- Issue 범위를 벗어나지 않습니다.
- 기존 이벤트 계약과 프로젝트 구조를 따릅니다.
- 보안 권한과 외부 API 호출을 사람이 확인합니다.
- 테스트를 실행합니다.
- PR에 LLM 사용 범위를 기록합니다.

## 문제 발생 시

Git 충돌, AWS 권한 오류, CI 실패를 임의로 무시하지 않습니다. 오류 메시지와 실행한 명령을 Issue나 PR에 남기고 팀에 공유합니다.
