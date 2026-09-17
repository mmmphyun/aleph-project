"""
scripts/verify_notion_api.py
실제 노션 칸반 카드 대상 연동 유무 확인 스크립트 (Python 버전).
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import UTC, datetime
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


def request_notion(key: str, path: str, method: str, payload: dict | None = None) -> dict:
    """Notion REST API 호출 헬퍼."""
    url = f"https://api.notion.com{path}"
    headers = {
        "Authorization": f"Bearer {key}",
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
    }
    data = json.dumps(payload).encode("utf-8") if payload else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    key = load_key()
    if not key:
        sys.stderr.write("오류: .env에 NOTION_API_KEY가 없습니다.\n")
        sys.exit(1)

    target_id = (sys.argv[1] if len(sys.argv) > 1 else "f8904d37c22583938ef201865f34ac9d").replace(
        "-", ""
    )

    print(f"[1/4] 대상 칸반 카드({target_id}) 메타데이터 조회...")
    card = request_notion(key, f"/v1/pages/{target_id}", "GET")
    title_objs = card.get("properties", {}).get("내용", {}).get("title", [])
    title = title_objs[0].get("plain_text") if title_objs else "제목 없음"
    orig_status = (
        card.get("properties", {}).get("상태", {}).get("status", {}).get("name", "시작 전")
    )
    print(f"  카드 제목: [{title}], 현재 상태: [{orig_status}]")

    print("\n[2/4] PR Open 시뮬레이션: 상태를 [검토 중]으로 전이 및 PR 링크 주입...")
    request_notion(
        key,
        f"/v1/pages/{target_id}",
        "PATCH",
        {
            "properties": {
                "상태": {"status": {"name": "검토 중"}},
                "PR": {"url": "https://github.com/mmmphyun/aleph-project/pull/1"},
            }
        },
    )
    print("  성공: '상태' -> [검토 중], 'PR' 반영 완료")

    print("\n[3/4] PR Merged 시뮬레이션: 상태를 [완료]로 전이, Commit SHA 주입 및 기간 갱신...")
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    existing_start = (
        card.get("properties", {}).get("기간", {}).get("date", {}).get("start") or today
    )
    request_notion(
        key,
        f"/v1/pages/{target_id}",
        "PATCH",
        {
            "properties": {
                "상태": {"status": {"name": "완료"}},
                "Commit": {
                    "rich_text": [{"type": "text", "text": {"content": "test-commit-sha-7f8e9d"}}]
                },
                "기간": {"date": {"start": existing_start, "end": today}},
            }
        },
    )
    print(
        f"  성공: '상태' -> [완료], 'Commit' 주입, '기간' -> [{existing_start} ~ {today}] 반영 완료"
    )

    print("\n[4/4] 카드 본문에 '기술 원리 요약' Callout 블록 추가...")
    request_notion(
        key,
        f"/v1/blocks/{target_id}/children",
        "PATCH",
        {
            "children": [
                {
                    "object": "block",
                    "type": "callout",
                    "callout": {
                        "rich_text": [
                            {
                                "type": "text",
                                "text": {
                                    "content": (
                                        "[PR #1 머지 완료] 기술 원리 요약\n\n"
                                        "1. GitHub Actions context에서 PR 메타데이터 비동기 추출\n"
                                        "2. Notion REST API v1/pages 및 v1/blocks "
                                        "엔드포인트를 통한 원자적 갱신\n"
                                        "3. DB 스키마('상태', 'PR', 'Commit', '기간') "
                                        "4단계 동기화 완료\n\n"
                                        "- PR: https://github.com/mmmphyun/aleph-project/pull/1\n"
                                        "- Commit: test-commit-sha-7f8e9d"
                                    ),
                                },
                            }
                        ],
                        "icon": {"type": "emoji", "emoji": "🛡️"},
                    },
                }
            ]
        },
    )
    print("  성공: 카드 본문에 기술 원리 요약 Callout 블록 정상 추가 완료!")


if __name__ == "__main__":
    main()
