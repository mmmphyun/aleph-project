/**
 * scripts/list_team_members.js
 * 노션 워크스페이스에 등록된 모든 팀원(User)의 이름, 이메일, ID(UUID)를 조회
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

https.get({
  hostname: "api.notion.com",
  path: "/v1/users",
  headers: {
    "Authorization": `Bearer ${key}`,
    "Notion-Version": "2022-06-28"
  }
}, res => {
  let b = "";
  res.on("data", c => b += c);
  res.on("end", () => {
    if (res.statusCode >= 200 && res.statusCode < 300) {
      const data = JSON.parse(b);
      console.log("=== 노션 워크스페이스 팀원 목록 ===");
      for (const u of data.results || []) {
        if (u.type === "person") {
          console.log(`- 이름: ${u.name || "(이름 없음)"}`);
          console.log(`  이메일: ${u.person?.email || "미공개"}`);
          console.log(`  User ID: ${u.id}`);
          console.log("");
        }
      }
      console.log("봇(통합) 계정:");
      for (const u of data.results || []) {
        if (u.type === "bot") {
          console.log(`- [Bot] ${u.name} (ID: ${u.id})`);
        }
      }
    } else {
      console.error(`조회 실패 (${res.statusCode}): ${b}`);
    }
  });
}).on("error", err => console.error(err.message));
