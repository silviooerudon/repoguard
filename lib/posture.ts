import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"

export type PostureGrade = "A" | "B" | "C" | "D" | "F"

export type PostureCategoryId = "branch" | "docs" | "deps"

export type PostureSignal = {
  id: string
  category: PostureCategoryId
  label: string
  pointsEarned: number
  pointsMax: number
  satisfied: boolean
}

export type PostureCategoryBreakdown = {
  id: PostureCategoryId
  label: string
  pointsEarned: number
  pointsMax: number
  signals: PostureSignal[]
}

export type QuickWin = {
  signalId: string
  label: string
  pointsAvailable: number
}

export type PostureResult = {
  score: number
  grade: PostureGrade
  breakdown: PostureCategoryBreakdown[]
  quickWins: QuickWin[]
  degraded: boolean
}

type RawSignals = {
  branchProtected: boolean
  hasSecurityMd: boolean
  hasLicense: boolean
  readmeContent: string | null
  hasDependabotOrRenovate: boolean
  hasLockfile: boolean
  gitignoreContent: string | null
  degraded: boolean
}

const QUICK_WIN_COPY: Record<string, string> = {
  "branch-protection": "Enable branch protection on main",
  "security-md": "Add SECURITY.md",
  "license": "Add a LICENSE file",
  "readme-substantial": "Expand README (at least 500 chars)",
  "readme-mentions-security": "Mention security/SECURITY.md in README",
  "auto-updates": "Enable Dependabot or Renovate",
  "lockfile": "Commit a lockfile (package-lock.json, yarn.lock, etc.)",
  "gitignore-basics": "Add node_modules and .env to .gitignore",
}

function buildGithubHeaders(token: string | null, accept: string): HeadersInit {
  const h: Record<string, string> = { Accept: accept }
  if (token) h.Authorization = `Bearer ${token}`
  return h
}

/**
 * Fetch raw file contents. Returns null on 404 or non-rate-limit error.
 * Throws GitHubRateLimitError if rate limited.
 * Throws on network errors so caller can flag degraded.
 */
async function fetchRepoFile(
  owner: string,
  repo: string,
  path: string,
  token: string | null,
): Promise<string | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
    {
      headers: buildGithubHeaders(token, "application/vnd.github.v3.raw"),
      cache: "no-store",
    },
  )
  if (res.status === 404) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    throw new Error(`GitHub fetch ${path} failed: ${res.status}`)
  }
  return res.text()
}

/**
 * Check existence without downloading content. Cheaper for large lockfiles.
 * Throws GitHubRateLimitError if rate limited.
 * Throws on network errors so caller can flag degraded.
 */
async function repoPathExists(
  owner: string,
  repo: string,
  path: string,
  token: string | null,
): Promise<boolean> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
    {
      headers: buildGithubHeaders(token, "application/vnd.github.v3.json"),
      cache: "no-store",
    },
  )
  if (res.status === 404) return false
  if (res.ok) return true
  const retry = parseGitHubRateLimit(res)
  if (retry !== null) throw new GitHubRateLimitError(retry)
  throw new Error(`GitHub exists-check ${path} failed: ${res.status}`)
}

/**
 * Fetch branch metadata. Returns null on 404. Throws on rate limit / other errors.
 */
async function fetchBranch(
  owner: string,
  repo: string,
  branch: string,
  token: string | null,
): Promise<{ protected: boolean } | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/branches/${branch}`,
    {
      headers: buildGithubHeaders(token, "application/vnd.github+json"),
      cache: "no-store",
    },
  )
  if (res.status === 404) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    throw new Error(`GitHub branch fetch failed: ${res.status}`)
  }
  const json = (await res.json()) as { protected?: boolean }
  return { protected: Boolean(json.protected) }
}

/**
 * Wrap a promise so that non-rate-limit errors resolve to a fallback value
 * and flag `degraded`. Rate limit errors propagate.
 */
async function softFail<T>(
  p: Promise<T>,
  fallback: T,
  degradedFlag: { value: boolean },
): Promise<T> {
  try {
    return await p
  } catch (err) {
    if (err instanceof GitHubRateLimitError) throw err
    degradedFlag.value = true
    return fallback
  }
}

function gradeFromScore(score: number): PostureGrade {
  if (score >= 90) return "A"
  if (score >= 75) return "B"
  if (score >= 60) return "C"
  if (score >= 40) return "D"
  return "F"
}

function readmeMentionsSecurity(readme: string): boolean {
  if (/security/i.test(readme)) return true
  if (/SECURITY\.md/i.test(readme)) return true
  return false
}

function gitignoreCoversBasics(content: string): boolean {
  // Match each on its own line (ignoring leading slash, whitespace, comments)
  const lines = content.split(/\r?\n/).map((l) => l.trim())
  const hasNodeModules = lines.some((l) =>
    /^\/?node_modules\/?$/.test(l) || /^\/?node_modules\b/.test(l),
  )
  const hasEnv = lines.some((l) =>
    /^\/?\.env(\..*)?$/.test(l) || /^\/?\.env\b/.test(l),
  )
  return hasNodeModules && hasEnv
}

export function computeScore(raw: RawSignals): PostureResult {
  const readme = raw.readmeContent ?? ""
  const readmeSubstantial = readme.length >= 500
  const readmeSecurity = readme.length > 0 && readmeMentionsSecurity(readme)
  const gitignoreOk =
    raw.gitignoreContent !== null && gitignoreCoversBasics(raw.gitignoreContent)

  const branchSignals: PostureSignal[] = [
    {
      id: "branch-protection",
      category: "branch",
      label: "Branch protection enabled on main",
      pointsEarned: raw.branchProtected ? 35 : 0,
      pointsMax: 35,
      satisfied: raw.branchProtected,
    },
  ]

  const docSignals: PostureSignal[] = [
    {
      id: "security-md",
      category: "docs",
      label: "SECURITY.md present",
      pointsEarned: raw.hasSecurityMd ? 15 : 0,
      pointsMax: 15,
      satisfied: raw.hasSecurityMd,
    },
    {
      id: "license",
      category: "docs",
      label: "LICENSE file present",
      pointsEarned: raw.hasLicense ? 10 : 0,
      pointsMax: 10,
      satisfied: raw.hasLicense,
    },
    {
      id: "readme-substantial",
      category: "docs",
      label: "README is substantial (>= 500 chars)",
      pointsEarned: readmeSubstantial ? 5 : 0,
      pointsMax: 5,
      satisfied: readmeSubstantial,
    },
    {
      id: "readme-mentions-security",
      category: "docs",
      label: "README mentions security or SECURITY.md",
      pointsEarned: readmeSecurity ? 5 : 0,
      pointsMax: 5,
      satisfied: readmeSecurity,
    },
  ]

  const depSignals: PostureSignal[] = [
    {
      id: "auto-updates",
      category: "deps",
      label: "Dependabot or Renovate configured",
      pointsEarned: raw.hasDependabotOrRenovate ? 15 : 0,
      pointsMax: 15,
      satisfied: raw.hasDependabotOrRenovate,
    },
    {
      id: "lockfile",
      category: "deps",
      label: "Lockfile committed",
      pointsEarned: raw.hasLockfile ? 10 : 0,
      pointsMax: 10,
      satisfied: raw.hasLockfile,
    },
    {
      id: "gitignore-basics",
      category: "deps",
      label: ".gitignore covers node_modules and .env",
      pointsEarned: gitignoreOk ? 5 : 0,
      pointsMax: 5,
      satisfied: gitignoreOk,
    },
  ]

  const sumPoints = (signals: PostureSignal[]) =>
    signals.reduce((acc, s) => acc + s.pointsEarned, 0)
  const sumMax = (signals: PostureSignal[]) =>
    signals.reduce((acc, s) => acc + s.pointsMax, 0)

  const breakdown: PostureCategoryBreakdown[] = [
    {
      id: "branch",
      label: "Branch protection",
      pointsEarned: sumPoints(branchSignals),
      pointsMax: sumMax(branchSignals),
      signals: branchSignals,
    },
    {
      id: "docs",
      label: "Documentation",
      pointsEarned: sumPoints(docSignals),
      pointsMax: sumMax(docSignals),
      signals: docSignals,
    },
    {
      id: "deps",
      label: "Dependency hygiene",
      pointsEarned: sumPoints(depSignals),
      pointsMax: sumMax(depSignals),
      signals: depSignals,
    },
  ]

  const score = breakdown.reduce((acc, c) => acc + c.pointsEarned, 0)
  const grade = gradeFromScore(score)

  const allSignals = [...branchSignals, ...docSignals, ...depSignals]
  const quickWins: QuickWin[] = allSignals
    .filter((s) => !s.satisfied)
    .sort((a, b) => b.pointsMax - a.pointsMax)
    .slice(0, 5)
    .map((s) => {
      const copy = QUICK_WIN_COPY[s.id] ?? s.label
      return {
        signalId: s.id,
        label: `${copy} (+${s.pointsMax} points)`,
        pointsAvailable: s.pointsMax,
      }
    })

  return {
    score,
    grade,
    breakdown,
    quickWins,
    degraded: raw.degraded,
  }
}

export async function assessPosture(
  owner: string,
  repo: string,
  accessToken: string | null,
): Promise<PostureResult> {
  const degradedFlag = { value: false }

  const [
    branch,
    securityMd,
    licenseBare,
    licenseMd,
    licenseTxt,
    readme,
    dependabot,
    renovate,
    npmLock,
    yarnLock,
    pnpmLock,
    poetryLock,
    gitignore,
  ] = await Promise.all([
    softFail(fetchBranch(owner, repo, "main", accessToken), null, degradedFlag),
    softFail(repoPathExists(owner, repo, "SECURITY.md", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "LICENSE", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "LICENSE.md", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "LICENSE.txt", accessToken), false, degradedFlag),
    softFail(fetchRepoFile(owner, repo, "README.md", accessToken), null, degradedFlag),
    softFail(repoPathExists(owner, repo, ".github/dependabot.yml", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "renovate.json", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "package-lock.json", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "yarn.lock", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "pnpm-lock.yaml", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "poetry.lock", accessToken), false, degradedFlag),
    softFail(fetchRepoFile(owner, repo, ".gitignore", accessToken), null, degradedFlag),
  ])

  const raw: RawSignals = {
    branchProtected: branch?.protected ?? false,
    hasSecurityMd: securityMd,
    hasLicense: licenseBare || licenseMd || licenseTxt,
    readmeContent: readme,
    hasDependabotOrRenovate: dependabot || renovate,
    hasLockfile: npmLock || yarnLock || pnpmLock || poetryLock,
    gitignoreContent: gitignore,
    degraded: degradedFlag.value,
  }

  return computeScore(raw)
}