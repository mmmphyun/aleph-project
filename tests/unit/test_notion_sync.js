/**
 * tests/unit/test_notion_sync.js
 * notion_sync.yml GitHub Actions 스크립트의 파싱 및 페이로드 생성 단위 검증
 */

const assert = require("assert");

// 1. 노션 URL/Page ID 추출 정규식
const regex = /(?:notion\.(?:so|site|com)|app\.notion\.com)\/(?:.*?[/-])?([0-9a-f]{32})(?:[/?#]|$)|\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b|[?&]p=([0-9a-f]{32})/i;

function extractPageId(body) {
  const match = body.match(regex);
  if (!match) return null;
  const rawId = match[1] || match[2] || match[3];
  return rawId.replace(/-/g, "").toLowerCase();
}

// 2. 기술 원리 3줄 요약 추출 정규식
const summaryRegex = /##\s*기술\s*원리\s*(?:3줄)?\s*요약[\r\n]+([\s\S]*?)(?=(?:[\r\n]+##)|(?:[\r\n]+---)|(?:[\r\n]+<details>)|$)/i;

function extractTechSummary(body) {
  const match = body.match(summaryRegex);
  return match ? match[1].trim() : null;
}

// 3. 제목 콜론 정제 함수
function getCleanTitle(rawTitle) {
  return rawTitle.replace(/^[^:]+:\s*/, "").trim() || rawTitle;
}

// --- 테스트 케이스 실행 ---

console.log("[TEST 1] 실제 사용자 노션 URL 파싱 테스트");
const actualUserUrl = "https://app.notion.com/p/A-d5f04d37c22582ad9e7f81acd36191d0";
const id1 = extractPageId(`연관 티켓: ${actualUserUrl}`);
assert.strictEqual(id1, "d5f04d37c22582ad9e7f81acd36191d0");
console.log("  PASS: 실제 노션 링크에서 32자리 ID 정상 추출 ->", id1);

console.log("[TEST 2] 다양한 노션 URL 변형 규격 테스트");
const variations = [
  { url: "https://www.notion.so/workspace/Task-Title-d5f04d37c22582ad9e7f81acd36191d0", expected: "d5f04d37c22582ad9e7f81acd36191d0" },
  { url: "https://myteam.notion.site/d5f04d37c22582ad9e7f81acd36191d0", expected: "d5f04d37c22582ad9e7f81acd36191d0" },
  { url: "https://notion.so/d5f04d37-c225-82ad-9e7f-81acd36191d0?v=123", expected: "d5f04d37c22582ad9e7f81acd36191d0" },
  { url: "https://app.notion.com/workspace?p=d5f04d37c22582ad9e7f81acd36191d0", expected: "d5f04d37c22582ad9e7f81acd36191d0" },
  { url: "티켓 ID: d5f04d37-c225-82ad-9e7f-81acd36191d0", expected: "d5f04d37c22582ad9e7f81acd36191d0" }
];

variations.forEach((tc, idx) => {
  const parsed = extractPageId(tc.url);
  assert.strictEqual(parsed, tc.expected);
  console.log(`  PASS: 케이스 ${idx + 1} (${tc.url.substring(0, 45)}...) -> ${parsed}`);
});

console.log("[TEST 3] PR 본문 기술 원리 3줄 요약 추출 테스트");
const samplePrBody = `
## 작업 개요
노션 연동 파이프라인 정합성 수정.

## 기술 원리 3줄 요약
1. GitHub Actions context에서 pull_request 메타데이터 비동기 추출.
2. Notion REST API v1/pages 및 v1/blocks 엔드포인트를 통한 원자적 상태 갱신.
3. 스키마 불일치 방지를 위한 단계별 4단 graceful fallback 설계.

## 체크리스트
- [x] ruff 통과
- [x] 단위 테스트 통과
`;

const summary = extractTechSummary(samplePrBody);
assert.ok(summary);
assert.ok(summary.includes("1. GitHub Actions context"));
assert.ok(summary.includes("3. 스키마 불일치 방지를 위한 단계별 4단 graceful fallback 설계."));
console.log("  PASS: 기술 원리 3줄 요약 정상 파싱");

console.log("[TEST 4] PR/이슈 제목 콜론 정제 테스트");
const sampleTitles = [
  { raw: "feat(cloud-a): 노션 연동 파이프라인 정합성 수정", expected: "노션 연동 파이프라인 정합성 수정" },
  { raw: "fix(security): SSH Brute Force 룰 오탐 수정", expected: "SSH Brute Force 룰 오탐 수정" },
  { raw: "단순 제목 테스트", expected: "단순 제목 테스트" }
];

sampleTitles.forEach(t => {
  const cleaned = getCleanTitle(t.raw);
  assert.strictEqual(cleaned, t.expected);
  console.log(`  PASS: [${t.raw}] -> [${cleaned}]`);
});

console.log("\n모든 notion_sync 로직 단위 테스트 성공 (100% PASS)");
