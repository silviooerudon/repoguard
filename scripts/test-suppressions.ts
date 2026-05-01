import {
  parseSuppressions,
  applySuppressions,
  findRuleIdForFinding,
  findAlternateRuleIds,
  getFindingPath,
} from "../lib/suppressions";
import type { AnyFinding } from "../lib/risk";

const findings: AnyFinding[] = [
  {
    kind: "secret",
    data: {
      patternId: "aws-access-key",
      patternName: "AWS Access Key",
      severity: "high",
      description: "Looks like an AWS access key ID.",
      filePath: "src/config.ts",
      lineNumber: 12,
      lineContent: "const KEY = 'AKIA••••••••EXAMPLE'",
      likelyTestFixture: false,
    },
  },
  {
    kind: "secret",
    data: {
      patternId: "entropy-high-secret",
      patternName: "High-entropy value in secret-like key",
      severity: "medium",
      description: "High-entropy value assigned to a secret-named key.",
      filePath: "config/.env.example",
      lineNumber: 3,
      lineContent: "API_SECRET=••••",
      likelyTestFixture: false,
    },
  },
  {
    kind: "secret",
    data: {
      patternId: "github-pat",
      patternName: "GitHub Personal Access Token",
      severity: "critical",
      description: "GitHub PAT detected.",
      filePath: "old/leaked.ts",
      lineNumber: 5,
      lineContent: "ghp_••••",
      likelyTestFixture: false,
      source: "history",
      commitSha: "abc123",
    },
  },
  {
    kind: "code",
    data: {
      ruleId: "js-ssrf-fetch-user-input",
      ruleName: "SSRF via fetch with user input",
      severity: "high",
      category: "ssrf",
      description: "User-controlled URL passed to fetch().",
      cwe: "CWE-918",
      filePath: "api/proxy.ts",
      lineNumber: 22,
      lineContent: "fetch(req.query.url)",
      likelyTestFixture: false,
    },
  },
  {
    kind: "iac",
    data: {
      ruleId: "dockerfile-user-root",
      ruleName: "Container runs as root",
      severity: "medium",
      category: "dockerfile",
      description: "Container does not drop privileges.",
      filePath: "Dockerfile",
      lineNumber: 5,
      lineContent: "USER root",
      remediation: "Add a non-root USER directive.",
    },
  },
  {
    kind: "sensitive-file",
    data: {
      kind: "private-key",
      name: "id_rsa",
      severity: "critical",
      description: "Private key committed to repo.",
      filePath: "deploy/keys/id_rsa",
      remediation: "Rotate and remove from history.",
    },
  },
  {
    kind: "dependency",
    data: {
      package: "lodash",
      version: "4.17.20",
      ecosystem: "npm",
      severity: "high",
      title: "Prototype pollution in lodash",
      ghsa: "GHSA-35jh-r3h4-6jhm",
      vulnerable_versions: "<4.17.21",
      cvss_score: 7.4,
      url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
      source: "package.json",
    },
  },
];

const ignoreFile = `# Comentário linha inicial
tests/** [reason="Test fixtures intentionally contain secrets"]

legacy/** [rule=secret/*] [reason=migration-legacy]
src/config.ts [rule=secret/aws-*] [expires=2024-01-01]
config/** [rule=entropy/*]
api/proxy.ts [rule=code/cwe-918]
Dockerfile [rule=iac/dockerfile]
deploy/keys/** [rule=sensitive-file/private-key]
package.json [rule=dependency/lodash]
`;

const failures: string[] = [];

function assert(label: string, ok: boolean): void {
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${label}`);
  if (!ok) failures.push(label);
}

function findingLabel(f: AnyFinding): string {
  const primary = findRuleIdForFinding(f);
  return `${f.kind} @ ${getFindingPath(f)} → ${primary}`;
}

const suppressions = parseSuppressions(ignoreFile);

console.log("=== PARSED SUPPRESSIONS ===");
console.log(`Total: ${suppressions.length}`);
for (const s of suppressions) {
  console.log(
    `  L${s.sourceLine}  path=${s.pathGlob}  rule=${s.ruleGlob ?? "(any)"}  expires=${
      s.expires ?? "(none)"
    }  reason=${s.reason ?? "(none)"}`,
  );
}

console.log("\n=== RULE IDS PER FINDING ===");
for (const f of findings) {
  const primary = findRuleIdForFinding(f);
  const alts = findAlternateRuleIds(f);
  console.log(`  ${f.kind} @ ${getFindingPath(f)}`);
  console.log(`    primary:    ${primary}`);
  console.log(`    alternates: [${alts.join(", ")}]`);
}

const result = applySuppressions(findings, suppressions);

console.log("\n=== KEPT ===");
console.log(`Count: ${result.kept.length}`);
for (const f of result.kept) {
  console.log(`  ${findingLabel(f)}`);
}

console.log("\n=== SUPPRESSED ===");
console.log(`Count: ${result.suppressed.length}`);
for (const sf of result.suppressed) {
  const f = sf.finding;
  console.log(
    `  ${findingLabel(f)}  ←  L${sf.suppression.sourceLine} [rule=${
      sf.suppression.ruleGlob ?? "(any)"
    }]  expired=${sf.expired}`,
  );
}

console.log("\n=== EXPIRED SUPPRESSIONS COUNT ===");
console.log(`  ${result.expiredSuppressionsCount}`);

console.log("\n=== ASSERTIONS ===");

const suppressedByPath = new Map<string, (typeof result.suppressed)[number]>();
for (const sf of result.suppressed) {
  suppressedByPath.set(getFindingPath(sf.finding), sf);
}
const keptPaths = new Set(
  result.kept.map((f) => getFindingPath(f)),
);

const sf1 = suppressedByPath.get("src/config.ts");
assert(
  "1. aws-access-key (src/config.ts) suppressed by line with expires=2024-01-01, expired=true",
  !!sf1 && sf1.suppression.expires === "2024-01-01" && sf1.expired === true,
);

const sf2 = suppressedByPath.get("config/.env.example");
assert(
  "2. entropy (config/.env.example) suppressed by config/** [rule=entropy/*]",
  !!sf2 &&
    sf2.suppression.pathGlob === "config/**" &&
    sf2.suppression.ruleGlob === "entropy/*",
);

assert(
  "3. github-pat history (old/leaked.ts) NOT suppressed → kept",
  keptPaths.has("old/leaked.ts") && !suppressedByPath.has("old/leaked.ts"),
);

const sf4 = suppressedByPath.get("api/proxy.ts");
assert(
  "4. code SSRF (api/proxy.ts) suppressed by code/cwe-918 (alternate, not primary)",
  !!sf4 &&
    sf4.suppression.ruleGlob === "code/cwe-918" &&
    findRuleIdForFinding(sf4.finding) === "code/js-ssrf-fetch-user-input",
);

const sf5 = suppressedByPath.get("Dockerfile");
assert(
  "5. iac dockerfile-user-root suppressed by iac/dockerfile (alternate, not primary)",
  !!sf5 &&
    sf5.suppression.ruleGlob === "iac/dockerfile" &&
    findRuleIdForFinding(sf5.finding) === "iac/dockerfile-user-root",
);

const sf6 = suppressedByPath.get("deploy/keys/id_rsa");
assert(
  "6. private-key suppressed by deploy/keys/** [rule=sensitive-file/private-key]",
  !!sf6 &&
    sf6.suppression.pathGlob === "deploy/keys/**" &&
    sf6.suppression.ruleGlob === "sensitive-file/private-key",
);

const sf7 = suppressedByPath.get("package.json");
assert(
  "7. lodash dependency suppressed by package.json [rule=dependency/lodash]",
  !!sf7 && sf7.suppression.ruleGlob === "dependency/lodash",
);

assert(
  "8. expiredSuppressionsCount === 1",
  result.expiredSuppressionsCount === 1,
);

console.log("\n=== GHSA ALTERNATE TEST ===");
const lodashFinding = findings[6];
const variantA = `package.json [rule=dependency/lodash]\n`;
const variantB = `package.json [rule=dependency/GHSA-35jh-r3h4-6jhm]\n`;

const resA = applySuppressions([lodashFinding], parseSuppressions(variantA));
const resB = applySuppressions([lodashFinding], parseSuppressions(variantB));

console.log(
  `  Variant A (rule=dependency/lodash): suppressed=${resA.suppressed.length}, kept=${resA.kept.length}`,
);
console.log(
  `  Variant B (rule=dependency/GHSA-35jh-r3h4-6jhm): suppressed=${resB.suppressed.length}, kept=${resB.kept.length}`,
);

assert(
  "Variant A: lodash suppressed via primary rule (dependency/lodash)",
  resA.suppressed.length === 1 && resA.kept.length === 0,
);
assert(
  "Variant B: lodash suppressed via alternate rule (dependency/<ghsa>)",
  resB.suppressed.length === 1 && resB.kept.length === 0,
);

console.log("");
if (failures.length === 0) {
  console.log(`ALL ASSERTIONS PASSED (${10} total)`);
  process.exit(0);
} else {
  console.log(`${failures.length} ASSERTION(S) FAILED:`);
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
}
