"""
scripts/get_my_tasks.py
노션 [프로젝트 일정] DB의 [시작 전] 티켓 목록 조회 헬퍼 (Python 버전에 해당)
"""

import json
import os
import re
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


role = "cloud-a"
if os.path.exists(".agent-role"):
    with open(".agent-role", encoding="utf-8") as f:
        role = f.read().strip()

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
            title = title_objs[0].get("plain_text", "(제목 없음)") if title_objs else "(제목 없음)"
            page_id = r.get("id", "").replace("-", "")
            page_url = f"https://notion.so/{page_id}"
            people = props.get("담당자", {}).get("people", [])
            assignees = ", ".join([p.get("name", "지정됨") for p in people]) if people else "미지정"
            print(f"  {idx}. [{title}] (담당자: {assignees}) -> {page_url}")
except Exception as e:
    print("조회 에러:", e)
