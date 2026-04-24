import { scanDependencies } from "../lib/deps"
import { scanPythonDependencies } from "../lib/python-deps"

const TOKEN = process.env.TEST_GITHUB_TOKEN ?? null
const OWNER = process.env.TEST_OWNER ?? "silviooerudon"
const REPO = process.env.TEST_REPO ?? "repoguard"

async function main() {
  console.log(`Scanning ${OWNER}/${REPO}...`)

  const npmResult = await scanDependencies(OWNER, REPO, TOKEN)
  console.log(
    `npm: ${npmResult.vulns.length} vulnerabilities, ${npmResult.lifecycleIssues.length} suspicious lifecycle scripts`,
  )

  const pyVulns = await scanPythonDependencies(OWNER, REPO, TOKEN)
  console.log(`PyPI: ${pyVulns.length} vulnerabilities`)

  console.log(
    JSON.stringify(
      { npm: npmResult, python: pyVulns },
      null,
      2,
    ),
  )
}

main().catch(console.error)
