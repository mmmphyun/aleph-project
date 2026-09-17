# CloudShield 단위 테스트: scripts 도구 동작 및 WIP 가드 검증
# 소유자: 클라우드 A (플랫폼 전담 영역)
"""scripts/get_my_tasks.py 및 scripts 도구의 WIP 하드가드와 역할 식별 단위 테스트."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# scripts 임포트 경로 확보
root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from scripts import get_my_tasks  # noqa: E402
from scripts.get_my_tasks import (  # noqa: E402
    check_open_pr_guard,
    detect_role_from_branch,
    get_current_role,
    load_env,
)


def test_wip_guard_blocks_when_open_pr_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    """동일 직무의 열린 PR이 존재할 때 sys.exit(1)로 차단하는지 검증."""
    mock_prs = [
        {
            "number": 45,
            "title": "feat(cloud-b): CW Agent 수집 설정",
            "headRefName": "feat/cloud-b-cw-agent-config",
            "url": "https://github.com/mmmphyun/aleph-project/pull/45",
        }
    ]

    def mock_run(*args: list[str], **kwargs: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=json.dumps(mock_prs),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", mock_run)
    monkeypatch.delenv("ALLOW_CONCURRENT_WIP", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        check_open_pr_guard("cloud-b")
    assert exc_info.value.code == 1


def test_wip_guard_bypasses_when_env_var_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """ALLOW_CONCURRENT_WIP=1 환경변수가 설정되었을 때 WIP 가드가 통과하는지 검증."""
    monkeypatch.setenv("ALLOW_CONCURRENT_WIP", "1")
    # 예외 없이 정상 반환되어야 함
    check_open_pr_guard("cloud-b")


def test_wip_guard_allows_when_no_open_pr(monkeypatch: pytest.MonkeyPatch) -> None:
    """열린 PR이 없거나 타 직무의 PR만 있을 때 차단 없이 통과하는지 검증."""
    mock_prs = [
        {
            "number": 30,
            "title": "feat(network): 모의 공격 스크립트 추가",
            "headRefName": "feat/network-attack-script",
            "url": "https://github.com/mmmphyun/aleph-project/pull/30",
        }
    ]

    def mock_run(*args: list[str], **kwargs: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=json.dumps(mock_prs),
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", mock_run)
    monkeypatch.delenv("ALLOW_CONCURRENT_WIP", raising=False)

    # cloud-b 직무에는 열린 PR이 없으므로 통과
    check_open_pr_guard("cloud-b")


def test_get_current_role_reads_agent_role_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """로컬 .agent-role 파일에서 직무를 정상 판별하는지 검증."""
    role_file = tmp_path / ".agent-role"
    role_file.write_text("security\n", encoding="utf-8")

    monkeypatch.setattr(
        get_my_tasks,
        "Path",
        lambda p: role_file if p == ".agent-role" else Path(p),
    )
    assert get_current_role() == "security"


def test_get_current_role_fail_closed_when_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    """직무 판별 실패 시 Fail-Closed(exit 1) 정책 검증."""
    monkeypatch.setattr(get_my_tasks.Path, "is_file", lambda self: False)
    monkeypatch.setattr(get_my_tasks, "get_current_git_branch", lambda: "main")
    monkeypatch.delenv("AGENT_ROLE", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        get_my_tasks.get_current_role()
    assert exc_info.value.code == 1


def test_detect_role_from_branch() -> None:
    """브랜치명 접두어 직무 매칭 검증."""
    assert detect_role_from_branch("feat/cloud-b-task") == "cloud-b"
    assert detect_role_from_branch("fix/security-fix") == "security"
    assert detect_role_from_branch("hotfix/cloud-a-urgent-fix") == "cloud-a"
    assert detect_role_from_branch("main") is None


def test_load_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """env 파일에서 NOTION_API_KEY 정상 추출 검증."""
    env_file = tmp_path / ".env"
    env_file.write_text('NOTION_API_KEY="secret_test_key_123"\n', encoding="utf-8")

    monkeypatch.setattr(get_my_tasks, "Path", lambda p: env_file if p == ".env" else Path(p))
    assert load_env() == "secret_test_key_123"
