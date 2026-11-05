"""
tests/unit/test_is_docs_only.py
is_docs_only.py 순수 문서 판별 엔진 단위 테스트.

Why:
    문서 변경 시 불필요한 단위 테스트 스킵과 코드 변경 시 강제 실행의
    Fail-Closed 무결성을 보장하기 위함.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# scripts 임포트 경로 확보
root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from scripts.is_docs_only import evaluate_changes, is_docs_only_file  # noqa: E402


@pytest.mark.parametrize(
    "file_path,expected",
    [
        # 허용 대상: 마크다운 및 정적 자산
        ("README.md", True),
        ("docs/roles/cloud-a/README.md", True),
        ("docs/roles/network/README.md", True),
        ("docs/assets/topology.png", True),
        ("docs/assets/demo.mp4", True),
        ("docs/assets/presentation.html", True),
        (".gitignore", True),
        ("LICENSE", True),
        (".agent-role", True),
        # 차단 대상: 파이썬 및 런타임 코드
        ("src/collector/cw_agent.py", False),
        ("src/contracts/events.py", False),
        ("src/detection/rules.py", False),
        ("src/remediation/boto3_blocker.py", False),
        ("tests/unit/test_network.py", False),
        ("tests/conftest.py", False),
        # 차단 대상: 인프라 및 자동화 스크립트
        ("infra/terraform/modules/vpc/main.tf", False),
        ("scripts/check.ps1", False),
        ("scripts/verify_rnr_scope.py", False),
        ("network/web_dir_scan.sh", False),
        (".github/workflows/ci.yml", False),
        # 차단 대상: 프로젝트 설정 파일
        ("pyproject.toml", False),
        ("uv.lock", False),
        ("amazon-cloudwatch-agent.json", False),
        ("nginx.conf", False),
        ("init_target_server.sh", False),
        # 엣지 케이스: docs 내부의 코드 및 실행 스크립트 차단
        ("docs/scripts/helper.py", False),
        ("docs/tools/exploit.sh", False),
        ("docs/infra/sample.tf", False),
        ("docs/config/settings.json", False),
    ],
)
def test_is_docs_only_file_classification(file_path: str, expected: bool) -> None:
    """단일 파일 경로가 문서 및 코드 기준에 따라 정확히 분류되는지 검증."""
    assert is_docs_only_file(file_path) is expected


def test_evaluate_changes_returns_true_for_all_docs() -> None:
    """모든 파일이 문서인 경우 True를 반환해야 함."""
    docs_files = [
        "README.md",
        "docs/roles/cloud-a/README.md",
        "docs/assets/topology.png",
    ]
    assert evaluate_changes(docs_files) is True


def test_evaluate_changes_returns_false_if_any_code_included() -> None:
    """문서 목록에 단 하나의 코드 파일이라도 포함되면 False를 반환해야 함."""
    mixed_files = [
        "README.md",
        "docs/roles/network/README.md",
        "src/contracts/events.py",
    ]
    assert evaluate_changes(mixed_files) is False


def test_evaluate_changes_returns_false_for_empty_list() -> None:
    """변경 파일이 없는 경우 안전을 위해 False(전체 테스트 실행)를 반환해야 함."""
    assert evaluate_changes([]) is False
