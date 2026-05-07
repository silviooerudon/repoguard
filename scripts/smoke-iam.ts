/**
 * Local smoke test for IAM parser and detectors.
 *
 * Reads .tf / .json / .yml files from a local fixture (TerraGoat clone),
 * runs the same extractStatements + detectors that production uses, and
 * prints a per-file summary plus all findings.
 *
 * Usage from repo root:
 *   npx tsx scripts/smoke-iam.ts ..\terragoat-fixture\terraform\aws
 *
 * If no path given, defaults to that path.
 */
import * as fs from "node:fs"
import * as path from "node:path"
import { detectPrivilegeEscalation } from "../lib/iam-privesc"
import { detectAdminEquivalents } from "../lib/iam-admin"
import * as iamModule from "../lib/iam"

type IamStatement = {
  effect: string | null
  principal: unknown
  actions: string[]
  resources: string[]
  conditions: unknown
  sourceLine: number | null
  rawSnippet: string
}

const extractStatements = (iamModule as unknown as {
  __testExtractStatements?: (content: string, filePath: string) => IamStatement[]
}).__testExtractStatements

if (!extractStatements) {
  console.error("ERROR: lib/iam.ts must export __testExtractStatements for this smoke.")
  process.exit(1)
}

const target = process.argv[2] ?? "..\\terragoat-fixture\\terraform\\aws"
const root = path.resolve(target)

if (!fs.existsSync(root)) {
  console.error(`ERROR: ${root} does not exist. Clone TerraGoat first:`)
  console.error("  git clone --depth 1 https://github.com/bridgecrewio/terragoat.git ..\\terragoat-fixture")
  process.exit(1)
}

function walk(dir: string): string[] {
  const out: string[] = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      out.push(...walk(full))
    } else {
      const lower = entry.name.toLowerCase()
      if (
        lower.endsWith(".tf") ||
        lower.endsWith(".json") ||
        lower.endsWith(".yml") ||
        lower.endsWith(".yaml")
      ) {
        out.push(full)
      }
    }
  }
  return out
}

const files = walk(root)
console.log(`Scanning ${files.length} files under ${root}\n`)

let totalStatements = 0
let totalFindings = 0
const findingsByRule = new Map<string, number>()

for (const file of files) {
  const content = fs.readFileSync(file, "utf-8")
  const stmts = extractStatements(content, file)
  totalStatements += stmts.length

  const privescFindings = detectPrivilegeEscalation(stmts as IamStatement[], file)
  const adminFindings = detectAdminEquivalents(stmts as IamStatement[], file)
  const allFindings = [...privescFindings, ...adminFindings]

  if (stmts.length === 0 && allFindings.length === 0) continue

  console.log(`${path.relative(root, file)}`)
  console.log(`  statements: ${stmts.length}`)
  if (stmts.length > 0 && stmts.length <= 3) {
    for (const s of stmts) {
      console.log(`    effect=${s.effect} actions=${JSON.stringify(s.actions.slice(0, 4))} resources=${JSON.stringify(s.resources.slice(0, 2))}`)
    }
  }
  if (allFindings.length > 0) {
    console.log(`  findings: ${allFindings.length}`)
    for (const f of allFindings) {
      console.log(`    [${f.severity}] ${f.ruleId}: ${f.ruleName}`)
      findingsByRule.set(f.ruleId, (findingsByRule.get(f.ruleId) ?? 0) + 1)
      totalFindings++
    }
  }
  console.log()
}

console.log("=".repeat(60))
console.log(`Total files scanned:  ${files.length}`)
console.log(`Total statements:     ${totalStatements}`)
console.log(`Total findings:       ${totalFindings}`)
if (findingsByRule.size > 0) {
  console.log(`\nFindings by rule:`)
  for (const [rule, count] of findingsByRule) {
    console.log(`  ${rule}: ${count}`)
  }
}
