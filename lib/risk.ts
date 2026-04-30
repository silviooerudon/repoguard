import type {
  SecretFinding,
  CodeFinding,
  IaCFinding,
  SensitiveFileFinding,
  DependencyFinding,
} from "./types"

export type AnyFinding =
  | { kind: "secret"; data: SecretFinding }
  | { kind: "code"; data: CodeFinding }
  | { kind: "iac"; data: IaCFinding }
  | { kind: "sensitive-file"; data: SensitiveFileFinding }
  | { kind: "dependency"; data: DependencyFinding }

export type PrioritizedFinding = AnyFinding & {
  score: number
}

export type RiskBreakdown = {
  critical: number
  high: number
  medium: number
  low: number
  fixture: number
}

export type RiskAssessment = {
  score: number
  breakdown: RiskBreakdown
  prioritized: PrioritizedFinding[]
}

export const SEVERITY_BASE_POINTS = {
  critical: 40,
  high: 15,
  medium: 5,
  moderate: 5,
  low: 1,
} as const

export const TEST_FIXTURE_MULTIPLIER = 0.1
export const TRANSITIVE_DEP_MULTIPLIER = 0.5
export const HISTORY_SECRET_MULTIPLIER = 0.5
export const REPO_SCORE_CAP = 100

export function scoreFinding(finding: AnyFinding): number {
  const sev = finding.data.severity as keyof typeof SEVERITY_BASE_POINTS
  let points = SEVERITY_BASE_POINTS[sev] ?? 0

  if ("likelyTestFixture" in finding.data && finding.data.likelyTestFixture) {
    points *= TEST_FIXTURE_MULTIPLIER
  }

  if (finding.kind === "secret" && finding.data.source === "history") {
    points *= HISTORY_SECRET_MULTIPLIER
  }

  if (finding.kind === "dependency" && finding.data.isTransitive) {
    points *= TRANSITIVE_DEP_MULTIPLIER
  }

  return points
}

export function prioritize(findings: AnyFinding[]): PrioritizedFinding[] {
  return findings
    .map((f) => ({ ...f, score: scoreFinding(f) }))
    .sort((a, b) => b.score - a.score)
}

export function scoreRepo(findings: AnyFinding[]): RiskAssessment {
  const prioritized = prioritize(findings)

  const breakdown: RiskBreakdown = {
    critical: 0, high: 0, medium: 0, low: 0, fixture: 0,
  }

  for (const f of prioritized) {
    const isFixture =
      "likelyTestFixture" in f.data && f.data.likelyTestFixture
    if (isFixture) {
      breakdown.fixture += f.score
      continue
    }
    const sev = f.data.severity
    if (sev === "critical") breakdown.critical += f.score
    else if (sev === "high") breakdown.high += f.score
    else if (sev === "medium" || sev === "moderate") breakdown.medium += f.score
    else if (sev === "low") breakdown.low += f.score
  }

  const total =
    breakdown.critical + breakdown.high + breakdown.medium +
    breakdown.low + breakdown.fixture

  return {
    score: Math.min(REPO_SCORE_CAP, Math.round(total)),
    breakdown,
    prioritized,
  }
}

type ScanLikeShape = {
  findings?: SecretFinding[]
  historyFindings?: SecretFinding[]
  codeFindings?: CodeFinding[]
  iacFindings?: IaCFinding[]
  sensitiveFiles?: SensitiveFileFinding[]
  dependencies?: DependencyFinding[]
  pythonDependencies?: DependencyFinding[]
}

export function flattenScan(scan: ScanLikeShape): AnyFinding[] {
  const out: AnyFinding[] = []
  for (const s of scan.findings ?? []) out.push({ kind: "secret", data: s })
  for (const s of scan.historyFindings ?? []) out.push({ kind: "secret", data: s })
  for (const c of scan.codeFindings ?? []) out.push({ kind: "code", data: c })
  for (const i of scan.iacFindings ?? []) out.push({ kind: "iac", data: i })
  for (const f of scan.sensitiveFiles ?? []) out.push({ kind: "sensitive-file", data: f })
  for (const d of scan.dependencies ?? []) out.push({ kind: "dependency", data: d })
  for (const d of scan.pythonDependencies ?? []) out.push({ kind: "dependency", data: d })
  return out
}
