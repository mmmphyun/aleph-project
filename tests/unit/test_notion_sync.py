# CloudShield 단위 테스트: notion_sync.yml 정규식 및 파싱 검증
# 소유자: 클라우드 A (플랫폼 전담 영역)
"""notion_sync.yml GitHub Actions 스크립트의 파싱 및 페이로드 생성 단위 검증 (Python 포팅 버전)."""

from __future__ import annotations

import re

# 1. 노션 URL/Page ID 추출 정규식 (notion_sync.yml과 동일)
NOTION_PAGE_REGEX = re.compile(
    r"(?:notion\.(?:so|site|com)|app\.notion\.com)\/(?:.*?[/-])?([0-9a-f]{32})(?![0-9a-f])"
    r"|\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"
    r"|[?&]p=([0-9a-f]{32})(?![0-9a-f])",
    re.IGNORECASE,
)


def extract_page_id(body: str) -> str | None:
    """PR/Issue 본문에서 노션 32자리 Page ID 추출."""
    match = NOTION_PAGE_REGEX.search(body)
    if not match:
        return None
    raw_id = match.group(1) or match.group(2) or match.group(3)
    return raw_id.replace("-", "").lower()


# 2. 기술적 원리 요약 추출 정규식 (notion_sync.yml과 동일)
SUMMARY_REGEX = re.compile(
    r"##\s*(?:\d+\.\s*)?기술(?:적)?\s*원리(?:\s*(?:3줄)?\s*요약)?(?:\s*\([^)]*\))?[\r\n]+"
    r"([\s\S]*?)(?=(?:[\r\n]+##)|(?:[\r\n]+---)|(?:[\r\n]+<details>)|$)",
    re.IGNORECASE,
)


def extract_tech_summary(body: str) -> str | None:
    """PR 본문에서 기술적 원리 요약 블록 추출."""
    match = SUMMARY_REGEX.search(body)
    return match.group(1).strip() if match else None


# 3. 제목 콜론 정제 함수
def get_clean_title(raw_title: str) -> str:
    """커밋/PR 컨벤션 접두어를 제거하고 순수 작업 제목 추출."""
    clean = re.sub(r"^[^:]+:\s*", "", raw_title).strip()
    return clean if clean else raw_title


def test_extract_page_id_standard_and_variations() -> None:
    """다양한 노션 URL 형식에서 32자리 Page ID 추출 검증."""
    expected = "d5f04d37c22582ad9e7f81acd36191d0"

    samples = [
        "https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0",
        "https://www.notion.so/workspace/Task-Title-d5f04d37c22582ad9e7f81acd36191d0",
        "https://myteam.notion.site/d5f04d37c22582ad9e7f81acd36191d0",
        "https://notion.so/d5f04d37-c225-82ad-9e7f-81acd36191d0?v=123",
        "https://app.notion.com/workspace?p=d5f04d37c22582ad9e7f81acd36191d0",
        "티켓 ID: d5f04d37-c225-82ad-9e7f-81acd36191d0",
    ]

    for sample in samples:
        extracted = extract_page_id(f"연관 티켓: {sample}")
        assert extracted == expected, f"추출 실패: {sample} -> {extracted}"


def test_extract_page_id_returns_none_when_no_match() -> None:
    """노션 URL이 없을 때 None 반환 검증."""
    assert extract_page_id("일반 텍스트만 있는 본문입니다.") is None
    assert extract_page_id("https://github.com/mmmphyun/aleph-project/pull/1") is None


def test_extract_tech_summary_official_and_variations() -> None:
    """PR 템플릿의 정규 및 변형 기술적 원리 요약 헤딩 추출 검증."""
    pr_body_official = """
## 1. 작업 개요
- Notion: https://notion.so/d5f04d37c22582ad9e7f81acd36191d0

## 3. 기술적 원리 요약 (1. 2. 3. 필수)
1. 첫 번째 원리
2. 두 번째 원리
3. 세 번째 원리

## 4. 로컬 테스트
- check.ps1 통과
"""
    summary = extract_tech_summary(pr_body_official)
    assert summary is not None
    assert "1. 첫 번째 원리" in summary
    assert "3. 세 번째 원리" in summary
    assert "## 4. 로컬 테스트" not in summary

    pr_body_variation = """
## 기술 원리 3줄 요약
- 비동기 처리
- 원자적 복합 차단

---
## 기타
"""
    summary_var = extract_tech_summary(pr_body_variation)
    assert summary_var is not None
    assert "- 비동기 처리" in summary_var
    assert "## 기타" not in summary_var


def test_get_clean_title() -> None:
    """PR 제목 정제 로직 검증."""
    assert get_clean_title("feat(cloud-b): CW Agent 수집 설정") == "CW Agent 수집 설정"
    assert get_clean_title("fix(ci): 린터 정규식 보강") == "린터 정규식 보강"
    assert get_clean_title("단순 제목") == "단순 제목"
