// scripts/smoke-supply-chain.ts
// Smoke test for Supply Chain Scanner.
// Run: npx tsx scripts/smoke-supply-chain.ts [<fixture-dir>]
// Default fixture: ../supply-chain-fixture
//
// E2: asserts specific typosquatting findings against expanded fixture.

import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import {
  scanSupplyChain,
  type SupplyChainFinding,
  type SupplyChainSeverity,
} from "../lib/supply-chain";

const DEFAULT_FIXTURE = join(process.cwd(), "..", "supply-chain-fixture");

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "venv",
  ".venv",
  "__pycache__",
]);

const MAX_FILE_BYTES = 1024 * 1024;

interface ExpectedFinding {
  package: string;
  target: string;
  severity: SupplyChainSeverity;
  pattern: string;
  ecosystem: "npm" | "pypi";
}

const EXPECTED_E2: ExpectedFinding[] = [
  // npm typosquats
  {
    package: "lodahs",
    target: "lodash",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "npm",
  },
  {
    package: "expres",
    target: "express",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "npm",
  },
  {
    package: "reactt",
    target: "react",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "npm",
  },
  {
    package: "Chalk",
    target: "chalk",
    severity: "HIGH",
    pattern: "case-fold",
    ecosystem: "npm",
  },
  {
    package: "lodashes",
    target: "lodash",
    severity: "MEDIUM",
    pattern: "edit-distance-2-prefix",
    ecosystem: "npm",
  },
  // pypi typosquats
  {
    package: "urllib33",
    target: "urllib3",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "pypi",
  },
  {
    package: "reqests",
    target: "requests",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "pypi",
  },
  {
    package: "flas",
    target: "flask",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "pypi",
  },
];

// These deps are legit and must NOT generate findings.
const FORBIDDEN_PACKAGES = [
  "axios",
  "my-internal-pkg",
  "requests",
  "numpy",
  "boto3",
  "django",
];

async function loadFiles(root: string): Promise<Map<string, string>> {
  const files = new Map<string, string>();

  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        await walk(full);
      } else if (e.isFile()) {
        const s = await stat(full);
        if (s.size > MAX_FILE_BYTES) continue;
        const rel = relative(root, full).split(sep).join("/");
        const content = await readFile(full, "utf-8").catch(() => "");
        files.set(rel, content);
      }
    }
  }

  await walk(root);
  return files;
}

function findingMatches(
  f: SupplyChainFinding,
  exp: ExpectedFinding,
): boolean {
  return (
    f.categoryId === "typosquatting" &&
    f.package === exp.package &&
    f.severity === exp.severity &&
    f.pattern === exp.pattern &&
    f.evidence.includes(`-> ${exp.target}`) &&
    f.evidence.includes(`ecosystem=${exp.ecosystem}`)
  );
}

async function main(): Promise<void> {
  const fixture = process.argv[2] || DEFAULT_FIXTURE;
  console.log(`Smoke supply chain against fixture: ${fixture}`);

  const files = await loadFiles(fixture);
  console.log(`  loaded ${files.size} files`);

  const result = await scanSupplyChain({ files });

  console.log("");
  console.log(`Score: ${result.score} (${result.level})`);
  console.log(`Findings: ${result.findings.length}`);
  console.log(`Scanned: ${JSON.stringify(result.scanned)}`);
  console.log("");
  console.log("Findings detail:");
  for (const f of result.findings) {
    console.log(
      `  [${f.severity}] ${f.categoryId} ${f.pattern}: ${f.message}` +
        (f.package ? ` (pkg=${f.package}, file=${f.file})` : ""),
    );
  }
  console.log("");

  let allOk = true;

  // 1. All expected findings must be present.
  for (const exp of EXPECTED_E2) {
    const found = result.findings.find((f) => findingMatches(f, exp));
    if (!found) {
      console.error(
        `MISSING: ${exp.package} -> ${exp.target} ` +
          `${exp.severity} ${exp.pattern} (${exp.ecosystem})`,
      );
      allOk = false;
    }
  }

  // 2. Forbidden (legit) deps must NOT generate findings.
  for (const pkg of FORBIDDEN_PACKAGES) {
    const wrong = result.findings.find((f) => f.package === pkg);
    if (wrong) {
      console.error(
        `FALSE POSITIVE: '${pkg}' is legit but flagged as ` +
          `${wrong.severity} ${wrong.pattern}`,
      );
      allOk = false;
    }
  }

  // 3. Minimum scan coverage sanity.
  if (result.scanned.depsAnalyzed === 0) {
    console.error("E2 FAIL: depsAnalyzed=0 - parsers not extracting deps");
    allOk = false;
  }

  // 4. No unexpected findings beyond the expected set.
  // (Soft check - only warn, do not fail. New seed packages may trigger additional matches.)
  const expectedKeys = new Set(
    EXPECTED_E2.map((e) => `${e.package}::${e.target}`),
  );
  const unexpected = result.findings.filter(
    (f) =>
      f.categoryId === "typosquatting" &&
      !expectedKeys.has(`${f.package}::${f.evidence.match(/-> ([\w\-.]+)/)?.[1]}`),
  );
  if (unexpected.length > 0) {
    console.warn("");
    console.warn(
      `Note: ${unexpected.length} unexpected typosquat finding(s) ` +
        `(may be from seed list updates, not necessarily a failure):`,
    );
    for (const f of unexpected) {
      console.warn(`  ${f.package} - ${f.evidence}`);
    }
  }

  if (!allOk) {
    console.error("");
    console.error("E2 FAIL");
    process.exit(1);
  }

  console.log(
    `E2 PASS - ${EXPECTED_E2.length} expected findings present, ` +
      `${FORBIDDEN_PACKAGES.length} legit deps not flagged, ` +
      `${result.scanned.depsAnalyzed} deps analyzed`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
