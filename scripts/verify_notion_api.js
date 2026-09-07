/**
 * scripts/verify_notion_api.js
 * 실제 노션 칸반 카드 대상 연동 유무 확인 스크립트
 */

const https = require("https");
const fs = require("fs");
const path = require("path");

function loadKey() {
  const envPath = path.resolve(process.cwd(), ".env");
  if (!fs.existsSync(envPath)) return null;
  const env = fs.readFileSync(envPath, "utf-8");
  const m = env.match(/NOTION_API_KEY\s*=\s*(.*)/);
  return m ? m[1].trim().replace(/^['"]|['"]$/g, "") : null;
}

const key = loadKey();
if (!key) {
  console.error("오류: .env에 NOTION_API_KEY가 없습니다.");
  process.exit(1);
}

// 기본 대상: "프로젝트 일정" DB의 "진행 중인 일" 카드
const targetCardId = (process.argv[2] || "f8904d37c22583938ef201865f34ac9d").replace(/-/g, "");

function requestNotion(reqPath, method, payload = null) {
  return new Promise((resolve, reject) => {
    const data = payload ? JSON.stringify(payload) : null;
    const options = {
      hostname: "api.notion.com",
      port: 443,
      path: reqPath,
      method: method,
      headers: {
        "Authorization": `Bearer ${key}`,
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json"
      }
    };
    if (data) options.headers["Content-Length"] = Buffer.byteLength(data);

    const req = https.request(options, res => {
      let b = "";
      res.on("data", c => b += c);
      res.on("end", () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ status: res.statusCode, data: JSON.parse(b || "{}") });
        } else {
          reject(new Error(`HTTP ${res.statusCode}: ${b}`));
        }
      });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

async function runTest() {
  console.log(`[1/4] 대상 칸반 카드(${targetCardId}) 메타데이터 조회...`);
  const card = await requestNotion(`/v1/pages/${targetCardId}`, "GET");
  const title = card.data.properties["내용"]?.title?.[0]?.plain_text || "제목 없음";
  const origStatus = card.data.properties["상태"]?.status?.name || "시작 전";
  console.log(`  카드 제목: [${title}], 현재 상태: [${origStatus}]`);

  console.log(`\n[2/4] PR Open 시뮬레이션: 상태를 [검토 중]으로 전이 및 PR 링크 주입...`);
  await requestNotion(`/v1/pages/${targetCardId}`, "PATCH", {
    properties: {
      "상태": { status: { name: "검토 중" } },
      "PR": { url: "https://github.com/mmmphyun/aleph-project/pull/1" }
    }
  });
  console.log("  성공: '상태' -> [검토 중], 'PR' -> [https://github.com/mmmphyun/aleph-project/pull/1] 반영 완료");

  console.log(`\n[3/4] PR Merged 시뮬레이션: 상태를 [완료]로 전이, Commit SHA 주입 및 기간(종료일) 갱신...`);
  const today = new Date().toISOString().split("T")[0];
  const existingStart = card.data.properties["기간"]?.date?.start || today;
  await requestNotion(`/v1/pages/${targetCardId}`, "PATCH", {
    properties: {
      "상태": { status: { name: "완료" } },
      "Commit": {
        rich_text: [{ type: "text", text: { content: "test-commit-sha-7f8e9d" } }]
      },
      "기간": {
        date: { start: existingStart, end: today }
      }
    }
  });
  console.log(`  성공: '상태' -> [완료], 'Commit' -> [test-commit-sha-7f8e9d], '기간' -> [${existingStart} ~ ${today}] 반영 완료`);

  console.log(`\n[4/4] 카드 본문에 '기술 원리 3줄 요약' Callout 블록 추가...`);
  await requestNotion(`/v1/blocks/${targetCardId}/children`, "PATCH", {
    children: [
      {
        object: "block",
        type: "callout",
        callout: {
          rich_text: [
            {
              type: "text",
              text: {
                content: "[PR #1 머지 완료] 기술 원리 요약\n\n1. GitHub Actions context에서 PR 메타데이터 비동기 추출\n2. Notion REST API v1/pages 및 v1/blocks 엔드포인트를 통한 원자적 갱신\n3. DB 스키마('상태', 'PR', 'Commit', '기간') 4단계 동기화 완료\n\n- PR: https://github.com/mmmphyun/aleph-project/pull/1\n- Commit: test-commit-sha-7f8e9d"
              }
            }
          ],
          icon: { type: "emoji", emoji: "🛡️" }
        }
      }
    ]
  });
  console.log("  성공: 카드 본문에 기술 원리 요약 Callout 블록 정상 추가 완료!");

  console.log("\n=======================================================");
  console.log("실제 노션 데이터 연동 테스트가 100% 성공했습니다.");
  console.log("노션의 [프로젝트 일정] 칸반 보드를 새로고침하여 확인해보십시오.");
  console.log("=======================================================");
}

runTest().catch(err => console.error("실패:", err.message));
