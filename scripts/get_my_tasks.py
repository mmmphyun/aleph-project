"""
scripts/get_my_tasks.py
노션 [프로젝트 일정] DB의 티켓 조회 헬퍼 및 WIP/순차 의존성 하드가드.

Why:
    선행 PR이 머지되기 전에 후속 작업을 착수하거나 이슈를 증식하는 행위를
    시스템 레벨에서 원천 차단하고, 작업자 직무에 맞는 노션 티켓을 자동 바인딩함.
    Phase 직렬 작업 구간에서는 [P<Phase>-<순서>] 포맷을 감지하여
    선행 티켓 미완료 시 조기 착수를 방지함.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any

PHASE_SEQ_PATTERN = re.compile(r"\[P(\d+)-(\d+)([A-Za-z]*)\]", re.IGNORECASE)


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
    """브랜치명 접두어(feat/<role>-*, fix/<role>-*, hotfix/<role>-*)로부터 직무 추출."""
    m = re.match(
        r"^(?:feat|fix|hotfix|chore|docs|refactor|test|style|perf|ci)/(cloud-a|cloud-b|security|network)(?:-|$)",
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


def parse_ticket_record(r: dict[str, Any]) -> dict[str, Any]:
    """노션 API 결과 레코드를 딕셔너리로 추출."""
    props = r.get("properties", {})
    title_objs = props.get("내용", {}).get("title", [])
    title = title_objs[0].get("plain_text", "(제목 없음)") if title_objs else "(제목 없음)"
    status_obj = props.get("상태", {}).get("status")
    status = status_obj.get("name", "미지정") if status_obj else "미지정"
    scenario_obj = props.get("시나리오", {}).get("select")
    scenario = scenario_obj.get("name", "기타") if scenario_obj else "기타"
    people = props.get("담당자", {}).get("people", [])
    assignees = ", ".join([p.get("name", "지정됨") for p in people]) if people else "미지정"
    page_id = r.get("id", "").replace("-", "")
    page_url = f"https://notion.so/{page_id}"

    # 직렬 순서 식별자 추출 [P<phase>-<step><substep>]
    m = PHASE_SEQ_PATTERN.search(title)
    seq_tuple = None
    if m:
        phase_num = int(m.group(1))
        step_num = int(m.group(2))
        sub_step = m.group(3).upper()
        seq_tuple = (phase_num, step_num, sub_step)

    return {
        "id": page_id,
        "title": title,
        "status": status,
        "scenario": scenario,
        "assignees": assignees,
        "url": page_url,
        "seq": seq_tuple,
    }


def query_all_notion_tickets(key: str, db_id: str) -> list[dict[str, Any]]:
    """노션 DB에서 전체 티켓을 페이지네이션으로 안전하게 수집."""
    url = f"https://api.notion.com/v1/databases/{db_id}/query"
    headers = {
        "Authorization": f"Bearer {key}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }

    all_results: list[dict[str, Any]] = []
    has_more = True
    start_cursor = None

    while has_more:
        payload_dict: dict[str, Any] = {"page_size": 100}
        if start_cursor:
            payload_dict["start_cursor"] = start_cursor

        payload = json.dumps(payload_dict).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("results", [])
            for r in results:
                all_results.append(parse_ticket_record(r))
            has_more = data.get("has_more", False)
            start_cursor = data.get("next_cursor")

    return all_results


def check_sequential_dependencies(
    my_tickets: list[dict[str, Any]], all_tickets: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], bool, str]]:
    """직렬 순서 식별자([P<phase>-<step><substep>])를 비교하여 선행 작업 완료 여부 판정.

    Returns:
        list of (ticket, is_ready, reason_message)
    """
    # 순서 식별자가 있는 전체 티켓만 필터링
    seq_tickets = [t for t in all_tickets if t["seq"] is not None]

    results: list[tuple[dict[str, Any], bool, str]] = []
    for ticket in my_tickets:
        my_seq = ticket["seq"]
        if my_seq is None:
            # 순서 식별자가 없는 일반 티켓은 즉시 착수 가능
            results.append((ticket, True, "병렬 티켓 (선행 의존성 없음)"))
            continue

        my_phase, my_step, my_sub = my_seq
        # 동일 Phase 내에서 나보다 앞선 순서의 티켓 탐색
        blocking_tickets = [
            t
            for t in seq_tickets
            if t["seq"][0] == my_phase
            and (t["seq"][1], t["seq"][2]) < (my_step, my_sub)
            and t["status"] != "완료"
        ]

        if blocking_tickets:
            # 선행 티켓 중 가장 빠른 미완료 티켓 정보 안내
            blocking_tickets.sort(key=lambda x: (x["seq"][1], x["seq"][2]))
            first_blocker = blocking_tickets[0]
            reason = (
                f"대기 중: 선행 티켓 '{first_blocker['title']}' "
                f"(상태: {first_blocker['status']}) 미완료"
            )
            results.append((ticket, False, reason))
        else:
            results.append((ticket, True, "선행 작업 완료됨 (착수 가능)"))

    return results


def main() -> None:
    """티켓 조회 및 WIP/순차 의존성 검사 엔트리포인트."""
    parser = argparse.ArgumentParser(description="노션 프로젝트 일정 티켓 조회 및 WIP 가드 도구")
    parser.add_argument(
        "--all",
        action="store_true",
        help="WIP 가드를 건너뛰고 전체 티켓의 상태 현황을 출력합니다.",
    )
    parser.add_argument(
        "--status",
        type=str,
        default=None,
        help="특정 상태의 티켓만 필터링합니다. (예: '시작 전', '진행 중', '검토 중', '완료')",
    )
    parser.add_argument(
        "--role",
        type=str,
        default=None,
        help="특정 직무의 티켓만 필터링합니다. (예: 'cloud-a', 'cloud-b', 'security', 'network')",
    )
    args = parser.parse_args()

    # 조회 모드가 아닌 착수 모드(기본)일 때만 엄격한 직무 감지 및 WIP 가드 수행
    is_view_mode = args.all or (args.status is not None) or (args.role is not None)

    if not is_view_mode:
        role = get_current_role()
        check_open_pr_guard(role)
    else:
        role = args.role or "all"

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

    try:
        all_tickets = query_all_notion_tickets(key, db_id)
    except Exception as e:
        sys.stderr.write(f"[노션 조회 오류] 티켓 조회 실패: {e}\n")
        sys.exit(1)

    # 1. 뷰 모드 처리 (--all, --status, --role)
    if is_view_mode:
        filtered = all_tickets
        if args.status:
            filtered = [t for t in filtered if t["status"] == args.status]
        if args.role and args.role != "all":
            filtered = [t for t in filtered if f"[{args.role}]" in t["title"].lower()]

        print("=" * 80)
        filter_summary = (
            f"필터 - 직무: [{args.role or '전체'}], 상태: [{args.status or '전체'}] | "
            f"조회 결과: {len(filtered)}건"
        )
        print(f"[노션 티켓 현황 뷰] {filter_summary}")
        print("=" * 80)
        for idx, t in enumerate(filtered, start=1):
            seq_str = f" [P{t['seq'][0]}-{t['seq'][1]}{t['seq'][2]}]" if t["seq"] else ""
            print(
                f"  {idx:2d}. [{t['status']:4s}]{seq_str} {t['title']} "
                f"(담당: {t['assignees']}) -> {t['url']}"
            )
        print("=" * 80)
        return

    # 2. 작업 착수 모드 (기본 실행: 내 직무의 시작 전 티켓 조회 및 순차 의존성 판정)
    role_tickets = [
        t
        for t in all_tickets
        if f"[{role}]" in t["title"].lower() or f"[{role.replace('-', ' ')}]" in t["title"].lower()
    ]
    my_todo_tickets = [t for t in role_tickets if t["status"] == "시작 전"]

    print(f"[노션 연동] 직무: [{role}] | '시작 전' 티켓 수: {len(my_todo_tickets)}건")
    if not my_todo_tickets:
        print("  (현재 노션에 등록된 '시작 전' 티켓이 없습니다. 신규 일감으로 진행합니다.)")
        return

    dep_checks = check_sequential_dependencies(my_todo_tickets, all_tickets)
    print("\n" + "=" * 80)
    print(f"[직무: {role}] 작업 착수 가이드 및 순차 의존성 검증 결과")
    print("=" * 80)
    for idx, (t, is_ready, reason) in enumerate(dep_checks, start=1):
        status_tag = "[착수 가능]" if is_ready else "[대기 필요]"
        print(f"  {idx}. {status_tag} {t['title']}")
        print(f"     * 상태: {t['status']} | 판정 사유: {reason}")
        print(f"     * 노션 링크: {t['url']}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
