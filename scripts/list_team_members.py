"""
scripts/list_team_members.py
노션 워크스페이스에 등록된 모든 팀원(User)의 이름, 이메일, ID(UUID)를 조회.

Why:
    노션 태스크 자동 할당 시 필요한 팀원별 고유 UUID를 조회하고 매핑하기 위한 도구.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path


def load_key() -> str | None:
    """루트 .env 파일에서 NOTION_API_KEY 추출."""
    env_path = Path(".env")
    if not env_path.is_file():
        return None
    content = env_path.read_text(encoding="utf-8")
    m = re.search(r"NOTION_API_KEY\s*=\s*(.*)", content)
    if m:
        return m.group(1).strip().strip("'\"")
    return None


def main() -> None:
    """노션 /v1/users 엔드포인트를 호출하여 팀원 목록을 출력."""
    key = load_key()
    if not key:
        sys.stderr.write("오류: .env에 NOTION_API_KEY가 없습니다.\n")
        sys.exit(1)

    url = "https://api.notion.com/v1/users"
    headers = {
        "Authorization": f"Bearer {key}",
        "Notion-Version": "2022-06-28",
    }

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("results", [])

            print("=== 노션 워크스페이스 팀원 목록 ===")
            for u in results:
                if u.get("type") == "person":
                    name = u.get("name") or "(이름 없음)"
                    email = u.get("person", {}).get("email") or "미공개"
                    user_id = u.get("id")
                    print(f"- 이름: {name}")
                    print(f"  이메일: {email}")
                    print(f"  User ID: {user_id}")
                    print("")

            print("봇(통합) 계정:")
            for u in results:
                if u.get("type") == "bot":
                    name = u.get("name") or "(이름 없음)"
                    user_id = u.get("id")
                    print(f"- [Bot] {name} (ID: {user_id})")
    except Exception as e:
        sys.stderr.write(f"조회 실패: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
