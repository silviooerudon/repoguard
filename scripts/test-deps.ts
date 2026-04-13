import { scanDependencies } from "../lib/deps";

const TOKEN = process.env.TEST_GITHUB_TOKEN!;
const OWNER = "silviooerudon";
const REPO = "repoguard";

async function main() {
  console.log(`Scanning ${OWNER}/${REPO}...`);
  const findings = await scanDependencies(OWNER, REPO, TOKEN);
  console.log(`Found ${findings.length} vulnerabilities:`);
  console.log(JSON.stringify(findings, null, 2));
}

main().catch(console.error);