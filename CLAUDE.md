# CloudShield - Claude Code Configuration

이 프로젝트는 CloudShield(클라우드 하이브리드 위협 탐지·자동 대응 파이프라인)입니다.
모든 작업 전 리포지토리 루트의 `AGENTS.md`와 `docs/project-memory.md`를 반드시 먼저 확인하고 준수하십시오.

## 필수 시작 절차
1. 루트의 `.agent-role` 파일을 읽어 사용자의 직무(`network`, `cloud-b`, `security`, `cloud-a`)를 확인하고 스코프를 잠그십시오.
   - 파일이 없고 프롬프트에도 직무가 명시되지 않은 경우, 첫 응답으로 직무를 질문하십시오.
2. 코딩 착수 전 해당 작업의 핵심 개념/원리를 사용자에게 2~3줄로 먼저 설명하십시오.
3. 타 직무의 디렉토리 및 `src/contracts/*.py`, `tests/test_contracts.py`, `tests/mock_data/**`, `.github/workflows/*.yml`, `pyproject.toml`은 임의 수정이 절대 금지되어 있습니다.

## 검증 및 커밋
- 작업 완료 전 로컬 검증: `powershell .\scripts\check.ps1`
- 커밋 메시지: `<type>(<scope>): <한글 요약>` (scope: network, cloud-a, cloud-b, security, infra, contract)
