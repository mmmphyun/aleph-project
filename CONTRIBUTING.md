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
git switch -c feat/event-normalizer
```

브랜치 이름은 [브랜치 전략](docs/branch-strategy.md)을 따릅니다.

## 로컬 환경 준비

Python 3.12 이상 3.15 미만 환경을 사용합니다.

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pre-commit install
```

검사 실행:

```bash
ruff check .
ruff format --check .
pytest
```

## 커밋

커밋은 하나의 작은 작업만 포함합니다.

```text
<영문 type>: <한국어 설명>
```

예시:

```text
feat: 비정상 로그인 이벤트 파서 추가
fix: 만료된 임시 권한 회수 오류 수정
docs: 이벤트 형식 문서화
```

## Pull Request

PR을 만들 때 템플릿의 모든 항목을 작성합니다. 특히 다음 내용을 빠뜨리지 않습니다.

- 실행한 검사와 결과
- IAM 또는 AWS 리소스 변경 여부
- LLM을 사용한 범위
- 리뷰어가 확인할 부분
- 알려진 한계

리뷰어가 승인하기 전에는 PR을 직접 Merge하지 않습니다.

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
