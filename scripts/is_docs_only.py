"""
scripts/is_docs_only.py
순수 문서 및 정적 자산 변경 여부 판별 엔진.

Why:
    마크다운 문서(*.md, docs/**) 및 정적 시각 자료 수정 시
    로컬(check.ps1)과 CI(ci.yml)에서 1,907개 전체 단위 테스트가 실행되는
    불필요한 시간 지연(약 3분)과 가상 환경 클럭 지터로 인한 Flaky 실패를 방지함.
    Fail-Closed 원칙에 따라 코드 변경이 조금이라도 의심되면 테스트를 강제 실행함.

Constraints:
    - 입력: Git diff 및 status 기반의 변경 파일 목록.
    - 출력:
        - 순수 문서/정적 자산만 변경된 경우: stdout "docs_only", exit code 0
        - 코드/설정 변경이 포함되거나 변경점이 없는 경우: stdout "code_changed", exit code 1
        - 오류 발생 시: stderr 메시지, exit code 1 (Fail-Closed)

Side-effects / Edge-cases:
    - git 저장소가 아니거나 commit 히스토리가 없는 환경에서는 exit code 1로 폴백하여
      안전하게 전체 테스트를 실행하도록 보장함.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# 코드 및 설정 변경으로 간주되는 디렉토리 접두사 (하나라도 포함 시 code_changed)
CODE_DIRECTORIES: tuple[str, ...] = (
    "src/",
    "tests/",
    "infra/",
    "scripts/",
    ".github/",
)

# 코드 및 실행 스크립트 확장자
CODE_EXTENSIONS: tuple[str, ...] = (
    ".py",
    ".sh",
    ".ps1",
    ".tf",
    ".hcl",
    ".tfvars",
    ".yml",
    ".yaml",
    ".toml",
    ".json",
)

# 핵심 인프라 및 프로젝트 설정 파일 (파일명 완전 일치)
CRITICAL_CONFIG_FILES: frozenset[str] = frozenset(
    {
        "pyproject.toml",
        "uv.lock",
        "poetry.lock",
        "amazon-cloudwatch-agent.json",
        "nginx.conf",
        "init_target_server.sh",
    }
)

# 순수 문서 및 정적 자산으로 허용되는 확장자 (화이트리스트)
DOCS_ALLOWED_EXTENSIONS: tuple[str, ...] = (
    ".md",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".mp4",
    ".webm",
    ".html",
    ".ico",
    ".drawio",
)

# 순수 문서 및 안전한 메타 파일 (파일명 완전 일치)
DOCS_ALLOWED_EXACT_FILES: frozenset[str] = frozenset(
    {
        ".gitignore",
        "LICENSE",
        ".agent-role",
    }
)


def get_changed_files() -> list[str]:
    """Git diff 및 status를 호출하여 현재 브랜치/작업 트리의 변경 파일 목록을 수집."""
    # 1. Base Commit 탐색
    base_commit = None
    # CI 환경(PR)인 경우 GITHUB_BASE_REF 우선 탐색
    base_ref = os.getenv("GITHUB_BASE_REF")
    candidates = [f"origin/{base_ref}", base_ref] if base_ref else []
    candidates.extend(["origin/main", "main"])

    for candidate in candidates:
        if not candidate:
            continue
        res = subprocess.run(
            ["git", "merge-base", "HEAD", candidate],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0 and res.stdout.strip():
            base_commit = res.stdout.strip()
            break

    changed: set[str] = set()

    # 2. Base Commit 대비 커밋된 변경 파일
    if base_commit:
        res = subprocess.run(
            ["git", "diff", "--name-only", base_commit, "HEAD"],
            capture_output=True,
            text=True,
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.strip():
                    changed.add(line.strip().replace("\\", "/"))

    # 3. Staged 변경 파일
    res = subprocess.run(
        ["git", "diff", "--name-only", "--cached"],
        capture_output=True,
        text=True,
    )
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            if line.strip():
                changed.add(line.strip().replace("\\", "/"))

    # 4. Working Tree 수정 파일
    res = subprocess.run(
        ["git", "diff", "--name-only"],
        capture_output=True,
        text=True,
    )
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            if line.strip():
                changed.add(line.strip().replace("\\", "/"))

    # 5. Untracked 신규 파일 (??)
    res = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
    )
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            clean = line.strip()
            if clean.startswith("??"):
                untracked = clean[2:].strip().replace("\\", "/")
                # 로컬 임시 파일은 변경 감지 대상에서 제외
                if not untracked.startswith(".tmp-"):
                    changed.add(untracked)

    return sorted(changed)


def is_docs_only_file(file_path: str) -> bool:
    """단일 파일 경로가 순수 문서 또는 정적 자산인지 엄격히 검증 (Fail-Closed)."""
    norm = file_path.replace("\\", "/").strip("/")

    # 1. 파일명 완전 일치 화이트리스트 검사
    base_name = Path(norm).name
    if norm in DOCS_ALLOWED_EXACT_FILES or base_name in DOCS_ALLOWED_EXACT_FILES:
        return True

    # 2. 핵심 인프라 및 프로젝트 설정 파일 차단
    if base_name in CRITICAL_CONFIG_FILES or norm in CRITICAL_CONFIG_FILES:
        return False

    # 3. 코드 디렉토리 차단
    for code_dir in CODE_DIRECTORIES:
        if norm.startswith(code_dir):
            return False

    # 4. 코드 확장자 차단
    for ext in CODE_EXTENSIONS:
        if norm.endswith(ext):
            return False

    # 5. docs/ 하위 파일 검증 (실행 코드 배제)
    if norm.startswith("docs/"):
        return True

    # 6. 루트 또는 기타 디렉토리의 허용된 문서/정적 자산 확장자 검증
    for ext in DOCS_ALLOWED_EXTENSIONS:
        if norm.endswith(ext):
            return True

    # 화이트리스트에 부합하지 않는 모든 파일은 코드로 간주 (Fail-Closed)
    return False


def evaluate_changes(changed_files: list[str]) -> bool:
    """모든 변경 파일이 순수 문서인지 평가.

    Returns:
        bool: 순수 문서 변경만 있는 경우 True, 코드 변경이 있거나 변경점이 없는 경우 False.
    """
    if not changed_files:
        # 변경점이 감지되지 않은 경우 기본 안전 모드로 전체 테스트 실행
        return False

    for file_path in changed_files:
        if not is_docs_only_file(file_path):
            return False

    return True


def main() -> int:
    try:
        changed_files = get_changed_files()
        if evaluate_changes(changed_files):
            print("docs_only")
            return 0
        else:
            print("code_changed")
            return 1
    except Exception as exc:
        sys.stderr.write(f"[is_docs_only 오류] 변경 내역 분석 실패: {exc}\n")
        print("code_changed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
