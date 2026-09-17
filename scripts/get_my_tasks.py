"""
scripts/get_my_tasks.py
노션 [프로젝트 일정] DB의 [시작 전] 티켓 목록 조회 헬퍼 및 WIP 하드가드.

Why:
    선행 PR이 머지되기 전에 후속 작업을 착수하거나 이슈를 증식하는 행위를
    시스템 레벨에서 원천 차단하고, 작업자 직무에 맞는 노션 티켓을 자동 바인딩함.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path


def load_env() -> str | None:
    """루트 .env 파일에서 NOTION_API_KEY 값을 파싱하여 반환."""
    env_path = Path(".env")
    if not env_path.is_file():
        return None
    content = env_path.read_text(encoding="utf-8")
    m = re.search(r"NOTION_API_KEY\s*=\s*(.*)", content)
    if m:
        return m.group(1).strip().strip("'\"")
    return None


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
    """브랜치명 접두어로부터 직무 추출."""
    m = re.match(
        r"^(?:feat|fix|chore|docs|refactor|test|style|perf|ci)/(cloud-a|cloud-b|security|network)(?:-|$)",
        branch_name,
    )
    if m:
        return m.group(1)
    return None


def get_current_role() -> str:
    """현재 작업자의 직무를 엄격히 감지 (Fail-Closed)."""
    # 1순위: .agent-role 파일
    agent_role_file = Path(".agent-role")
    if agent_role_file.is_file():
        role = agent_role_file.read_text(encoding="utf-8").strip()
        if role:
            return role

    # 2순위: 현재 브랜치명
    branch = get_current_git_branch()
    branch_role = detect_role_from_branch(branch)
    if branch_role:
        return branch_role

    # 3순위: 환경변수 AGENT_ROLE
    env_role = os.getenv("AGENT_ROLE", "").strip()
    if env_role:
        return env_role

    sys.stderr.write(
        "[WIP 가드 오류] 직무를 식별할 수 없습니다 (Fail-Closed).\n"
        "프로젝트 루트에 .agent-role 파일을 생성하거나 "
        "git checkout -b feat/<직무>-... 로 브랜치를 설정하세요.\n"
    )
    sys.exit(1)


def check_open_pr_guard(current_role: str) -> None:
    """현재 직무의 열린 PR 존재 여부를 검사하는 WIP 1개 제한 하드가드."""
    if os.getenv("ALLOW_CONCURRENT_WIP") == "1":
        print("[WIP 가드 예외] ALLOW_CONCURRENT_WIP=1 설정으로 열린 PR 검사를 우회합니다.")
        return

    try:
        res = subprocess.run(
            ["gh", "pr", "list", "--state", "open", "--json", "number,title,headRefName,url"],
            capture_output=True,
            text=True,
            check=True,
        )
        prs = json.loads(res.stdout or "[]")
        role_prs = []
        for pr in prs:
            head_ref = pr.get("headRefName") or ""
            title = pr.get("title") or ""
            branch_match = head_ref.startswith(f"feat/{current_role}-") or head_ref.startswith(
                f"fix/{current_role}-"
            )
            title_match = f"({current_role}):" in title or f"[{current_role}]" in title
            if branch_match or title_match:
                role_prs.append(pr)

        if role_prs:
            sys.stderr.write("\n" + "=" * 80 + "\n")
            sys.stderr.write(
                f"[WIP 제한 차단] 직무 [{current_role}]에 아직 머지되지 않은 열린 PR이 "
                f"{len(role_prs)}건 존재합니다!\n"
            )
            sys.stderr.write("=" * 80 + "\n")
            for pr in role_prs:
                sys.stderr.write(f"  * PR #{pr.get('number')}: {pr.get('title')}\n")
                sys.stderr.write(f"    브랜치: {pr.get('headRefName')} | 링크: {pr.get('url')}\n")
            sys.stderr.write(
                "\n[작업 가이드라인 - PR 스태킹 및 이슈 증식 절대 금지]\n"
                "1. 신규 이슈(gh issue create)를 발행하거나 후속 티켓 브랜치를 분기하지 마십시오.\n"
                "2. 리뷰 피드백 수정 시 새 이슈를 따지 말고, "
                "기존 PR 브랜치에서 추가 커밋(fix/test) 후 푸시하십시오.\n"
                "3. 기존 PR의 리뷰 해결 및 머지가 완료된 후에만 다음 티켓에 착수할 수 있습니다.\n"
                + "=" * 80
                + "\n\n"
            )
            sys.exit(1)
    except subprocess.CalledProcessError as err:
        sys.stderr.write(f"[WIP 가드 경고] GitHub PR 상태 확인 실패 (gh CLI 확인 필요): {err}\n")
    except SystemExit:
        raise
    except Exception as err:
        sys.stderr.write(f"[WIP 가드 경고] GitHub PR 상태 확인 중 알 수 없는 오류 발생: {err}\n")


def main() -> None:
    """WIP 가드 검증 후 노션 '시작 전' 티켓 목록 출력."""
    role = get_current_role()
    check_open_pr_guard(role)

    key = load_env()
    if not key:
        print(f"[노션 연동 안내] 직무: [{role}]")
        print("  NOTION_API_KEY 미설정으로 노션 자동 조회를 건너뜁니다.")
        print("  노션 웹 칸반 보드에서 해당 일감 카드의 링크를 복사한 후,")
        print("  아래 명령어로 GitHub Issue를 생성하세요:")
        body_str = "- Notion Task: <복사한_노션_카드_URL>\\n- 브랜치: feat/<직무>-<기능명>"
        print(f'  gh issue create --title "feat({role}): <작업_제목>" --body "{body_str}"')
        sys.exit(0)

    db_id = "b8204d37c225838bb8de017940440498"
    url = f"https://api.notion.com/v1/databases/{db_id}/query"
    headers = {
        "Authorization": f"Bearer {key}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }
    payload = json.dumps({"filter": {"property": "상태", "status": {"equals": "시작 전"}}}).encode(
        "utf-8"
    )

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            results = res.get("results", [])
            print(f"[노션 연동] 직무: [{role}] | 전체 '시작 전' 티켓 수: {len(results)}건")
            if not results:
                print("  (현재 노션에 등록된 '시작 전' 티켓이 없습니다. 신규 일감으로 진행합니다.)")
            for idx, r in enumerate(results, start=1):
                props = r.get("properties", {})
                title_objs = props.get("내용", {}).get("title", [])
                title = (
                    title_objs[0].get("plain_text", "(제목 없음)") if title_objs else "(제목 없음)"
                )
                page_id = r.get("id", "").replace("-", "")
                page_url = f"https://notion.so/{page_id}"
                people = props.get("담당자", {}).get("people", [])
                assignees = (
                    ", ".join([p.get("name", "지정됨") for p in people]) if people else "미지정"
                )
                print(f"  {idx}. [{title}] (담당자: {assignees}) -> {page_url}")
    except Exception as e:
        sys.stderr.write(f"조회 에러: {e}\n")


if __name__ == "__main__":
    main()
