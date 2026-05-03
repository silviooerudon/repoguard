import { assessPosture } from "../lib/posture"

async function main() {
  const token = process.env.GITHUB_TOKEN ?? null
  if (!token) {
    console.warn("[warn] GITHUB_TOKEN not set; first scan will run anonymously and may hit rate limits.\n")
  }

  console.log("=== silviooerudon/repoguard (with token) ===")
  try {
    const r1 = await assessPosture("silviooerudon", "repoguard", token)
    console.log(JSON.stringify(r1, null, 2))
  } catch (err) {
    console.error("FAILED:", err)
    process.exitCode = 1
  }

  console.log("\n=== octocat/Hello-World (no token) ===")
  try {
    const r2 = await assessPosture("octocat", "Hello-World", null)
    console.log(JSON.stringify(r2, null, 2))
  } catch (err) {
    console.error("FAILED:", err)
    process.exitCode = 1
  }
}

main().catch((e) => { console.error(e); process.exit(1) })