# CloudShield 단위 테스트: scripts/verify_rnr_scope.py R&R 스코프 하드가드 검증
# 소유자: 클라우드 A (플랫폼 전담 영역)
"""verify_rnr_scope.py의 화이트리스트 매칭, 직무 식별, 사칭 차단 및 Fail-Closed 단위 테스트."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# scripts 디렉토리 임포트 지원
root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from scripts import verify_rnr_scope  # noqa: E402
from scripts.verify_rnr_scope import (  # noqa: E402
    RNR_WHITELIST,
    detect_role_from_branch,
    is_file_allowed,
    resolve_role,
)


def test_whitelist_matching_for_cloud_b() -> None:
    """클라우드 B 허용 화이트리스트(nginx.conf, test_target_server.py 포함) 및 차단 검증."""
    patterns = RNR_WHITELIST["cloud-b"]

    # 1. 허용되어야 하는 파일들
    assert is_file_allowed("nginx.conf", patterns)
    assert is_file_allowed("init_target_server.sh", patterns)
    assert is_file_allowed("amazon-cloudwatch-agent.json", patterns)
    assert is_file_allowed("src/collector/cw_processor.py", patterns)
    assert is_file_allowed("src/reporter/slack_notifier.py", patterns)
    assert is_file_allowed("tests/unit/test_collector.py", patterns)
    assert is_file_allowed("tests/unit/test_reporter.py", patterns)
    assert is_file_allowed("tests/unit/test_target_server.py", patterns)
    assert is_file_allowed("docs/roles/cloud-b/2026-09-09-target-server-init.md", patterns)
    assert is_file_allowed("docs/shared/meetings/meeting.md", patterns)
    assert is_file_allowed(".agent-role", patterns)

    # 2. 반드시 차단되어야 하는 타 직무 / 플랫폼 파일들
    assert not is_file_allowed("scripts/check.ps1", patterns)
    assert not is_file_allowed("scripts/verify_rnr_scope.py", patterns)
    assert not is_file_allowed("src/contracts/events.py", patterns)
    assert not is_file_allowed("src/contracts/incident.py", patterns)
    assert not is_file_allowed("src/remediation/remediation.py", patterns)
    assert not is_file_allowed("infra/terraform/main.tf", patterns)
    assert not is_file_allowed(".github/workflows/ci.yml", patterns)
    assert not is_file_allowed("tests/test_contracts.py", patterns)
    assert not is_file_allowed("tests/conftest.py", patterns)


def test_whitelist_matching_for_security() -> None:
    """보안 허용 화이트리스트 및 차단 검증."""
    patterns = RNR_WHITELIST["security"]

    # 1. 허용 대상
    assert is_file_allowed("src/detection/rules.py", patterns)
    assert is_file_allowed("src/detection/llm_analyzer.py", patterns)
    assert is_file_allowed("tests/unit/test_rules.py", patterns)
    assert is_file_allowed("tests/unit/test_llm_analyzer.py", patterns)
    assert is_file_allowed("docs/roles/security/report.md", patterns)
    assert is_file_allowed("docs/shared/ideas/idea.md", patterns)

    # 2. 차단 대상
    assert not is_file_allowed("src/contracts/events.py", patterns)
    assert not is_file_allowed("src/remediation/remediation.py", patterns)
    assert not is_file_allowed("src/collector/cw_processor.py", patterns)
    assert not is_file_allowed("scripts/check.ps1", patterns)


def test_whitelist_matching_for_network() -> None:
    """네트워크 허용 화이트리스트 및 차단 검증."""
    patterns = RNR_WHITELIST["network"]

    # 1. 허용 대상
    assert is_file_allowed("network/attack_simulation.sh", patterns)
    assert is_file_allowed("network/lab/Dockerfile", patterns)
    assert is_file_allowed("tests/unit/test_network.py", patterns)
    assert is_file_allowed("docs/roles/network/report.md", patterns)

    # 2. 차단 대상
    assert not is_file_allowed("src/contracts/events.py", patterns)
    assert not is_file_allowed("src/detection/rules.py", patterns)
    assert not is_file_allowed("scripts/check.ps1", patterns)


def test_whitelist_matching_for_cloud_a() -> None:
    """클라우드 A(플랫폼 전담)는 전 영역 허용 검증."""
    patterns = RNR_WHITELIST["cloud-a"]

    assert is_file_allowed("scripts/check.ps1", patterns)
    assert is_file_allowed("src/contracts/events.py", patterns)
    assert is_file_allowed("infra/terraform/main.tf", patterns)
    assert is_file_allowed(".github/workflows/ci.yml", patterns)
    assert is_file_allowed("any/path/whatsoever.py", patterns)


def test_detect_role_from_branch() -> None:
    """브랜치명 규격으로부터 직무 추출 정규식 검증."""
    assert detect_role_from_branch("feat/cloud-b-cw-agent") == "cloud-b"
    assert detect_role_from_branch("fix/security-regex-fix") == "security"
    assert detect_role_from_branch("feat/network-docker-lab") == "network"
    assert detect_role_from_branch("chore/cloud-a-harness") == "cloud-a"
    assert detect_role_from_branch("main") is None
    assert detect_role_from_branch("feat/unknown-feature") is None


def test_resolve_role_ci_actor_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI 환경에서 GitHub Actor 강제 매핑 및 정상 통과 검증."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("PR_AUTHOR", "wkdtlgns99-cell")
    monkeypatch.setenv("PR_HEAD_REF", "feat/cloud-b-collector-test")

    assert resolve_role() == "cloud-b"


def test_resolve_role_ci_blocks_spoofing(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI 환경에서 작성자 직무와 브랜치명 불일치(Role Spoofing) 시 차단 검증."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("PR_AUTHOR", "wkdtlgns99-cell")  # cloud-b 계정
    monkeypatch.setenv("PR_HEAD_REF", "feat/cloud-a-orchestrator")  # cloud-a 브랜치 사칭

    with pytest.raises(SystemExit) as exc_info:
        resolve_role()
    assert exc_info.value.code == 1


def test_resolve_role_ci_blocks_unregistered_actor(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI 환경에서 미등록 GitHub 계정 차단 검증."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("PR_AUTHOR", "unregistered-hacker")

    with pytest.raises(SystemExit) as exc_info:
        resolve_role()
    assert exc_info.value.code == 1


def test_resolve_role_local_agent_role_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """로컬 환경에서 .agent-role 파일 기반 직무 판별 검증."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    role_file = tmp_path / ".agent-role"
    role_file.write_text("security\n", encoding="utf-8")

    monkeypatch.setattr(
        verify_rnr_scope,
        "Path",
        lambda p: role_file if p == ".agent-role" else Path(p),
    )
    assert resolve_role() == "security"


def test_resolve_role_local_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """로컬 환경에서 직무 식별 불가 시 Fail-Closed(exit 1) 검증."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("AGENT_ROLE", raising=False)
    # .agent-role 파일 부재 모킹
    monkeypatch.setattr(verify_rnr_scope.Path, "is_file", lambda self: False)
    # branch 식별 불가 모킹
    monkeypatch.setattr(verify_rnr_scope, "get_current_git_branch", lambda: "main")

    with pytest.raises(SystemExit) as exc_info:
        resolve_role()
    assert exc_info.value.code == 1


def test_main_blocks_violations(monkeypatch: pytest.MonkeyPatch) -> None:
    """main() 실행 시 위반 파일이 존재하면 sys.exit(1)로 차단하는지 통합 검증."""
    monkeypatch.setattr(verify_rnr_scope, "resolve_role", lambda: "cloud-b")
    # cloud-b 작업자가 scripts/check.ps1를 변경한 상황 모킹
    monkeypatch.setattr(
        verify_rnr_scope,
        "get_changed_files",
        lambda: ["src/collector/cw_processor.py", "scripts/check.ps1"],
    )

    with pytest.raises(SystemExit) as exc_info:
        verify_rnr_scope.main()
    assert exc_info.value.code == 1


def test_main_allows_valid_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    """main() 실행 시 허용된 변경 파일만 존재하면 정상 종료(0)하는지 통합 검증."""
    monkeypatch.setattr(verify_rnr_scope, "resolve_role", lambda: "cloud-b")
    monkeypatch.setattr(
        verify_rnr_scope,
        "get_changed_files",
        lambda: [
            "src/collector/cw_processor.py",
            "nginx.conf",
            "tests/unit/test_target_server.py",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        verify_rnr_scope.main()
    assert exc_info.value.code == 0
