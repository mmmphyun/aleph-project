/**
 * scripts/get_my_tasks.js
 * 노션 [프로젝트 일정] DB의 [시작 전] 티켓 목록 조회 헬퍼
 * 
 * 기능:
 * 1. WIP 1개 제한 하드 가드: 현재 직무(.agent-role)에 아직 머지되지 않은 열린 PR이 있으면 신규 티켓 조회 차단
 * 2. 노션 DB 쿼리: 시작 전 상태인 티켓 목록 출력
 */

const https = require("https");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

function loadEnv() {
  const envPath = path.resolve(process.cwd(), ".env");
  if (!fs.existsSync(envPath)) return null;
  const env = fs.readFileSync(envPath, "utf-8");
  const m = env.match(/NOTION_API_KEY\s*=\s*(.*)/);
  return m ? m[1].trim().replace(/^['"]|['"]$/g, "") : null;
}

let role = "cloud-a";
if (fs.existsSync(".agent-role")) {
  role = fs.readFileSync(".agent-role", "utf-8").trim();
}

// ===========================================================================
// WIP(Work In Progress) 1개 제한 하드 가드 (PR Stacking 및 이슈 증식 차단)
// ===========================================================================
function checkOpenPrGuard(currentRole) {
  if (process.env.ALLOW_CONCURRENT_WIP === "1") {
    console.log("[WIP 가드 예외] ALLOW_CONCURRENT_WIP=1 설정으로 열린 PR 검사를 우회합니다.");
    return;
  }

  try {
    const stdout = execSync("gh pr list --state open --json number,title,headRefName,url", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
    });
    const prs = JSON.parse(stdout || "[]");

    // 현재 직무의 브랜치 접두사 또는 타이틀 스코프 매칭
    const rolePrs = prs.filter(pr => {
      const branchMatch = pr.headRefName && pr.headRefName.startsWith(`feat/${currentRole}-`) || pr.headRefName.startsWith(`fix/${currentRole}-`);
      const titleMatch = pr.title && (pr.title.includes(`(${currentRole}):`) || pr.title.includes(`[${currentRole}]`));
      return branchMatch || titleMatch;
    });

    if (rolePrs.length > 0) {
      console.error("\n" + "=".repeat(80));
      console.error(`[WIP 제한 차단] 직무 [${currentRole}]에 아직 머지되지 않은 열린 PR이 ${rolePrs.length}건 존재합니다!`);
      console.error("=".repeat(80));
      rolePrs.forEach(pr => {
        console.error(`  * PR #${pr.number}: ${pr.title}`);
        console.error(`    브랜치: ${pr.headRefName} | 링크: ${pr.url}`);
      });
      console.error("\n[작업 가이드라인 - PR 스태킹 및 이슈 증식 절대 금지]");
      console.error("1. 신규 이슈(gh issue create)를 발행하거나 후속 티켓 브랜치를 분기하지 마십시오.");
      console.error("2. 리뷰 피드백 수정 시 새 이슈를 따지 말고, 기존 PR 브랜치에서 추가 커밋(fix/test) 후 푸시하십시오.");
      console.error("3. 기존 PR의 리뷰 해결 및 머지가 완료된 후에만 다음 티켓에 착수할 수 있습니다.");
      console.error("=".repeat(80) + "\n");
      process.exit(1);
    }
  } catch (err) {
    // gh CLI 미설치 또는 비로그인 상태일 때는 경고 출력 후 계속 진행
    console.warn(`[WIP 가드 경고] GitHub PR 상태 확인 실패 (gh CLI 확인 필요): ${err.message}`);
  }
}

// WIP 검증 실행
checkOpenPrGuard(role);

const key = loadEnv();
if (!key) {
  console.log(`[노션 연동 안내] 직무: [${role}]`);
  console.log("  NOTION_API_KEY 미설정으로 노션 자동 조회를 건너뜁니다.");
  console.log("  노션 웹 칸반 보드에서 해당 일감 카드의 링크를 복사한 후, 아래 명령어로 GitHub Issue를 생성하세요:");
  console.log(`  gh issue create --title "feat(${role}): <작업_제목>" --body "- Notion Task: <복사한_노션_카드_URL>\\n- 브랜치: feat/<직무>-<기능명>"`);
  process.exit(0);
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
