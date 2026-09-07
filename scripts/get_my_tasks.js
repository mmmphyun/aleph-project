/**
 * scripts/get_my_tasks.js
 * 노션 [프로젝트 일정] DB의 [시작 전] 티켓 목록 조회 헬퍼
 * 하드코딩된 개인 식별자 없이 동작하며, .env의 설정 또는 직무(.agent-role)를 기반으로 동작
 */

const https = require("https");
const fs = require("fs");
const path = require("path");

function loadEnv() {
  const envPath = path.resolve(process.cwd(), ".env");
  if (!fs.existsSync(envPath)) return null;
  const env = fs.readFileSync(envPath, "utf-8");
  const m = env.match(/NOTION_API_KEY\s*=\s*(.*)/);
  return m ? m[1].trim().replace(/^['"]|['"]$/g, "") : null;
}

const key = loadEnv();
if (!key) {
  console.log("NOTION_API_KEY 미설정으로 노션 조회를 건너뜁니다.");
  process.exit(0);
}

let role = "cloud-a";
if (fs.existsSync(".agent-role")) {
  role = fs.readFileSync(".agent-role", "utf-8").trim();
}

const dbId = "b8204d37c225838bb8de017940440498"; // 프로젝트 일정 DB

const payload = JSON.stringify({
  filter: {
    property: "상태",
    status: { equals: "시작 전" }
  }
});

const req = https.request({
  hostname: "api.notion.com",
  port: 443,
  path: `/v1/databases/${dbId}/query`,
  method: "POST",
  headers: {
    "Authorization": `Bearer ${key}`,
    "Notion-Version": "2022-06-28",
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload)
  }
}, res => {
  let b = "";
  res.on("data", c => b += c);
  res.on("end", () => {
    if (res.statusCode >= 200 && res.statusCode < 300) {
      const data = JSON.parse(b);
      console.log(`[노션 연동] 직무: [${role}] | 전체 '시작 전' 티켓 수: ${data.results.length}건`);
      if (data.results.length === 0) {
        console.log("  (현재 노션에 등록된 '시작 전' 티켓이 없습니다. 신규 일감으로 진행합니다.)");
      }
      data.results.forEach((r, idx) => {
        const title = r.properties["내용"]?.title?.[0]?.plain_text || "(제목 없음)";
        const pageId = r.id.replace(/-/g, "");
        const url = `https://notion.so/${pageId}`;
        const assignees = (r.properties["담당자"]?.people || []).map(p => p.name || "지정됨").join(", ") || "미지정";
        console.log(`  ${idx + 1}. [${title}] (담당자: ${assignees}) -> ${url}`);
      });
    } else {
      console.log(`조회 실패 (${res.statusCode}): ${b}`);
    }
  });
});

req.on("error", err => console.log("조회 에러:", err.message));
req.write(payload);
req.end();
