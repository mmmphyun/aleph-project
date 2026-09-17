"""
scripts/verify_rnr_scope.py
CloudShield R&R(Role & Responsibility) 경계선 하드가드 검증 엔진.

Why:
    타 직무의 고유 포트폴리오 영역 및 플랫폼 독점 자산(scripts, contracts, infra 등)에 대한
    무단 수정을 로컬(check.ps1) 및 CI(ci.yml) 단계에서 기계적으로 100% 차단함.
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path

# 직무별 GitHub 계정 매핑 (CI 환경 강제 기준)
CI_ACTOR_MAP: dict[str, str] = {
    "mmmphyun": "cloud-a",
    "wkdtlgns99-cell": "cloud-b",
    "gkacksdnjs22-stack": "security",
    "RockCandy444": "network",
}

# 직무별 허용 파일 화이트리스트 매트릭스 (AGENTS.md 제2조 및 제2.2조 반영)
RNR_WHITELIST: dict[str, list[str]] = {
    "network": [
        "network/**",
        "tests/unit/test_network.py",
        "docs/roles/network/**",
        "docs/shared/**",
    ],
    "cloud-b": [
        "src/collector/**",
        "src/reporter/**",
        "tests/unit/test_collector.py",
        "tests/unit/test_reporter.py",
        "tests/unit/test_target_server.py",
        "amazon-cloudwatch-agent.json",
        "init_target_server.sh",
        "nginx.conf",
        "docs/roles/cloud-b/**",
        "docs/shared/**",
    ],
    "security": [
        "src/detection/**",
        "tests/unit/test_rules.py",
        "tests/unit/test_llm_analyzer.py",
        "tests/unit/test_incident_mapper.py",
        "docs/roles/security/**",
        "docs/shared/**",
        "scripts/verify_rnr_scope.py",
        "tests/unit/test_rnr_scope.py",
    ],
    "cloud-a": [
        "**",  # 플랫폼 전담: 전 영역 허용
    ],
}

# 검증에서 제외할 로컬/임시 메타 파일
IGNORED_FILES: set[str] = {
    ".agent-role",
    ".env",
    ".env.example",
}


def is_file_allowed(file_path: str, patterns: list[str]) -> bool:
    """단일 파일 경로가 주어진 화이트리스트 패턴 목록에 매합하는지 판별."""
    norm_path = file_path.replace("\\", "/").strip("/")
    if norm_path in IGNORED_FILES:
        return True

    for pat in patterns:
        if pat == "**":
            return True
        if pat.endswith("/**"):
            prefix = pat[:-3]
            if norm_path == prefix or norm_path.startswith(prefix + "/"):
                return True
        elif "*" in pat:
            if fnmatch.fnmatchcase(norm_path, pat):
                return True
        else:
            if norm_path == pat:
                return True
    return False


def get_current_git_branch() -> str:
    """현재 체크아웃된 Git 브랜치명 반환."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return ""


def detect_role_from_branch(branch_name: str) -> str | None:
    """브랜치명 접두어(feat/<role>-*, fix/<role>-*, hotfix/<role>-*)로부터 직무 추출."""
    m = re.match(
        r"^(?:feat|fix|hotfix|chore|docs|refactor|test|style|perf|ci)/(cloud-a|cloud-b|security|network)(?:-|$)",
        branch_name,
    )
    if m:
        return m.group(1)
    return None


def resolve_role() -> str:
    """현재 환경(CI 또는 로컬)에 따라 작업자의 직무를 엄격히 결정 (Fail-Closed)."""
    is_ci = os.getenv("GITHUB_ACTIONS") == "true"

    if is_ci:
        actor = os.getenv("PR_AUTHOR") or os.getenv("GITHUB_ACTOR") or ""
        role = CI_ACTOR_MAP.get(actor)
        if not role:
            sys.stderr.write(
                f"[R&R 차단] CI 환경에서 등록되지 않은 GitHub 계정({actor})입니다. "
                f"등록된 팀원 계정: {list(CI_ACTOR_MAP.keys())}\n"
            )
            sys.exit(1)

        # 브랜치명 교차 검증: 타 직무 브랜치 사칭(Role Spoofing) 차단
        head_ref = os.getenv("PR_HEAD_REF") or os.getenv("GITHUB_HEAD_REF") or ""
        branch_role = detect_role_from_branch(head_ref)
        if branch_role and branch_role != role:
            sys.stderr.write(
                f"[R&R 차단] 역할 사칭(Spoofing) 감지: GitHub 계정 [{actor}]의 직무는 "
                f"[{role}]이나, PR 브랜치명([{head_ref}])은 [{branch_role}] 영역입니다.\n"
            )
            sys.exit(1)

        return role

    # 로컬 환경 판별
    # 1순위: .agent-role 파일
    agent_role_file = Path(".agent-role")
    if agent_role_file.is_file():
        content = agent_role_file.read_text(encoding="utf-8").strip()
        if content in RNR_WHITELIST:
            return content

    # 2순위: 현재 git 브랜치명
    branch = get_current_git_branch()
    branch_role = detect_role_from_branch(branch)
    if branch_role in RNR_WHITELIST:
        return branch_role

    # 3순위: 환경변수 AGENT_ROLE
    env_role = os.getenv("AGENT_ROLE", "").strip()
    if env_role in RNR_WHITELIST:
        return env_role

    # 식별 실패 시 Fail-Closed
    sys.stderr.write(
        "[R&R 차단] 작업자의 직무를 식별할 수 없습니다 (Fail-Closed).\n"
        "다음 중 하나를 수행하여 역할을 명시하십시오:\n"
        "  1. 프로젝트 루트에 .agent-role 파일 생성 (예: 'cloud-b')\n"
        "  2. 'feat/<직무>-<기능명>' 형식의 브랜치로 전환\n"
        "  3. $env:AGENT_ROLE = '<직무>' 환경변수 설정\n"
    )
    sys.exit(1)


def get_changed_files() -> list[str]:
    """Git diff 및 status를 분석하여 변경·추가된 모든 파일 목록을 추출."""
    # 1. Base Commit 탐색
    base_commit = None
    for candidate in ["origin/main", "main"]:
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
            line_clean = line.strip()
            if line_clean.startswith("??"):
                untracked_path = line_clean[2:].strip().replace("\\", "/")
                changed.add(untracked_path)

    return sorted(changed)


def main() -> None:
    """R&R 스코프 검증 엔트리포인트."""
    role = resolve_role()
    allowed_patterns = RNR_WHITELIST.get(role, [])

    # 클라우드 A(플랫폼 전담)는 전 영역 허용
    if role == "cloud-a":
        print(f"[R&R 검증 통과] 직무: [{role}] (플랫폼 전담 - 전 영역 수정 권한 보유)")
        sys.exit(0)

    changed_files = get_changed_files()
    if not changed_files:
        print(f"[R&R 검증 통과] 직무: [{role}] (변경 파일 없음)")
        sys.exit(0)

    violations: list[str] = []
    for file_path in changed_files:
        if not is_file_allowed(file_path, allowed_patterns):
            violations.append(file_path)

    if violations:
        sys.stderr.write("\n" + "=" * 80 + "\n")
        sys.stderr.write(
            f"[R&R 경계선 침범 차단] 직무 [{role}] 권한 외 파일 변경이 감지되었습니다!\n"
        )
        sys.stderr.write("=" * 80 + "\n")
        sys.stderr.write("위반 파일 목록:\n")
        for v in violations:
            sys.stderr.write(f"  - {v}\n")
        sys.stderr.write("\n허용된 화이트리스트 규칙:\n")
        for p in allowed_patterns:
            sys.stderr.write(f"  * {p}\n")
        sys.stderr.write(
            "\n[조치 안내] AGENTS.md 제2조에 따라 타 직무 영역이나 "
            "플랫폼 공통 자산(scripts, contracts 등)은\n"
            "직접 수정할 수 없습니다. 담당 직무 영역 내의 파일만 수정하십시오.\n"
        )
        sys.stderr.write("=" * 80 + "\n\n")
        sys.exit(1)

    print(f"[R&R 검증 통과] 직무: [{role}] ({len(changed_files)}개 파일 변경 검증 완료)")
    sys.exit(0)


if __name__ == "__main__":
    main()
