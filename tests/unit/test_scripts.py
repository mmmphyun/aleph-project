# CloudShield 단위 테스트: scripts/get_my_tasks.py WIP 하드 가드 검증
# 소유자: 클라우드 B / 플랫폼 공통
"""scripts/get_my_tasks.py 스크립트의 WIP 1개 제한 하드 가드 단위 및 회귀 테스트."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# 프로젝트 루트 경로를 sys.path에 추가하여 CI(Linux/pytest) 환경에서도 scripts 패키지 참조 보장
root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from scripts.get_my_tasks import check_open_pr_guard  # noqa: E402


def test_wip_guard_blocks_when_open_pr_exists(monkeypatch: pytest.MonkeyPatch) -> None:
    """같은 직무의 열린 PR이 존재할 때 WIP 가드가 sys.exit(1)로 차단하는지 검증.

    Why:
        AGENTS.md 4.1 지침에 따라 동일 직무에 열린 PR이 존재하는 경우
        신규 이슈 발행 및 PR 스태킹을 시스템 레벨에서 차단함.
    """
    mock_prs = [
        {
            "number": 45,
            "title": "feat(cloud-b): CW Agent 수집 설정 및 타임스탬프 검증",
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
    """ALLOW_CONCURRENT_WIP=1 환경변수가 설정되었을 때 WIP 가드가 차단하지 않는지 검증."""
    monkeypatch.setenv("ALLOW_CONCURRENT_WIP", "1")

    # 차단 없이 예외 우회 로그 출력 후 정상 반환해야 함
    check_open_pr_guard("cloud-b")


def test_wip_guard_allows_when_no_open_pr(monkeypatch: pytest.MonkeyPatch) -> None:
    """열린 PR이 없거나 타 직무의 PR만 존재할 때 WIP 가드가 차단하지 않고 경과하는지 검증."""
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

    # cloud-b 직무에는 열린 PR이 없으므로 sys.exit 없이 무사 반환
    check_open_pr_guard("cloud-b")
