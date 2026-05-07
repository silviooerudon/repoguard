// scripts/smoke-supply-chain.ts
// Smoke test for Supply Chain Scanner against a local fixture.
// Run: npx tsx scripts/smoke-supply-chain.ts [<fixture-dir>]
// Default fixture: ../supply-chain-fixture (sibling of repoguard repo)
//
// E1: validates plumbing only - expects 0 findings (no detectors wired yet).
// E2-E4: will assert specific findings as detectors come online.

import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { scanSupplyChain } from "../lib/supply-chain";

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

  for (const f of result.findings) {
    console.log(
      `  [${f.severity}] ${f.categoryId} ${f.pattern}: ${f.message}` +
        (f.package ? ` (pkg=${f.package})` : ""),
    );
  }

  // E1 expectation: detectors not yet wired -> 0 findings.
  // Any non-zero result here means something accidentally fires before E2.
  if (result.findings.length !== 0) {
    console.error("");
    console.error("E1 FAIL: expected 0 findings (detectors not yet wired)");
    process.exit(1);
  }

  // Sanity: at least one manifest should be detected by the scanner.
  const totalManifests =
    result.scanned.packageJsonCount +
    result.scanned.setupPyCount +
    result.scanned.pyprojectCount;

  if (totalManifests === 0) {
    console.error("");
    console.error(
      "E1 FAIL: fixture has no package.json / setup.py / pyproject.toml - " +
        "scanner has nothing to chew on. Check fixture path.",
    );
    process.exit(1);
  }

  console.log("");
  console.log(`E1 PASS - plumbing OK, ${totalManifests} manifest(s) detected`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
