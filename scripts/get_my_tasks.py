"""
scripts/get_my_tasks.py
노션 [프로젝트 일정] DB의 [시작 전] 티켓 목록 조회 헬퍼 (Python 버전에 해당)
"""

import json
import os
import re
import subprocess
import sys
import urllib.request


def load_env():
    env_path = os.path.join(os.getcwd(), ".env")
    if not os.path.exists(env_path):
        return None
    with open(env_path, encoding="utf-8") as f:
        content = f.read()
    m = re.search(r"NOTION_API_KEY\s*=\s*(.*)", content)
    if m:
        return m.group(1).strip().strip("'\"")
    return None


def check_open_pr_guard(current_role: str) -> None:
    """현재 직무(.agent-role)의 열린 PR 존재 여부를 검사하는 WIP 1개 제한 하드 가드.

    Why:
        선행 PR이 머지되기 전에 신규 이슈를 발행하거나 후속 브랜치를 쌓는 행위
        (PR Stacking 및 이슈 증식)를 시스템 차원에서 차단하여 AGENTS.md 4.1 지침을 보장함.
    """
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
            print("\n" + "=" * 80, file=sys.stderr)
            msg = (
                f"[WIP 제한 차단] 직무 [{current_role}]에 아직 머지되지 않은 열린 PR이 "
                f"{len(role_prs)}건 존재합니다!"
            )
            print(msg, file=sys.stderr)
            print("=" * 80, file=sys.stderr)
            for pr in role_prs:
                print(f"  * PR #{pr.get('number')}: {pr.get('title')}", file=sys.stderr)
                print(
                    f"    브랜치: {pr.get('headRefName')} | 링크: {pr.get('url')}",
                    file=sys.stderr,
                )
            print(
                "\n[작업 가이드라인 - PR 스태킹 및 이슈 증식 절대 금지]",
                file=sys.stderr,
            )
            print(
                "1. 신규 이슈(gh issue create)를 발행하거나 후속 티켓 브랜치를 분기하지 마십시오.",
                file=sys.stderr,
            )
            print(
                "2. 리뷰 피드백 수정 시 새 이슈를 따지 말고, "
                "기존 PR 브랜치에서 추가 커밋(fix/test) 후 푸시하십시오.",
                file=sys.stderr,
            )
            print(
                "3. 기존 PR의 리뷰 해결 및 머지가 완료된 후에만 다음 티켓에 착수할 수 있습니다.",
                file=sys.stderr,
            )
            print("=" * 80 + "\n", file=sys.stderr)
            sys.exit(1)
    except subprocess.CalledProcessError as err:
        print(
            f"[WIP 가드 경고] GitHub PR 상태 확인 실패 (gh CLI 확인 필요): {err}",
            file=sys.stderr,
        )
    except Exception as err:
        print(
            f"[WIP 가드 경고] GitHub PR 상태 확인 중 알 수 없는 오류 발생: {err}",
            file=sys.stderr,
        )


def get_current_role() -> str:
    """현재 작업자의 직무(.agent-role 파일 우선, 기본값 cloud-a)를 반환.

    Why:
        로컬 및 CI 환경에서 작업자 역할을 일관되게 감지하고,
        테스트 환경에서 역할(role) 모킹을 용이하게 하여 환경 격리를 보장함.
    """
    if os.path.exists(".agent-role"):
        with open(".agent-role", encoding="utf-8") as f:
            return f.read().strip()
    return "cloud-a"


def main() -> None:
    """스크립트 엔트리포인트: WIP 하드 가드 확인 및 노션 DB 조회 수행."""
    role = get_current_role()

    # 노션 키 확인 및 안내 출력 전에 최우선으로 WIP 하드 가드 수행
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
        print("조회 에러:", e)


if __name__ == "__main__":
    main()
