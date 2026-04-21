import { SECRET_PATTERNS, type SecretPattern } from "./secret-patterns"

export class GitHubRateLimitError extends Error {
  readonly retryAfterSeconds: number
  constructor(retryAfterSeconds: number) {
    super(`GitHub API rate limit exceeded. Retry in ${retryAfterSeconds}s.`)
    this.name = "GitHubRateLimitError"
    this.retryAfterSeconds = retryAfterSeconds
  }
}

export class GitHubRepoNotFoundError extends Error {
  readonly owner: string
  readonly repo: string
  constructor(owner: string, repo: string) {
    super(`Repository ${owner}/${repo} not found or inaccessible.`)
    this.name = "GitHubRepoNotFoundError"
    this.owner = owner
    this.repo = repo
  }
}

/**
 * Returns retry-after seconds if the response indicates GitHub rate limiting,
 * otherwise null. Handles primary rate limit (403 + x-ratelimit-remaining: 0)
 * and secondary/abuse rate limit (429 with Retry-After header).
 */
export function parseGitHubRateLimit(response: Response): number | null {
  if (response.status !== 403 && response.status !== 429) return null

  const remaining = response.headers.get("x-ratelimit-remaining")
  const reset = response.headers.get("x-ratelimit-reset")
  const retryAfter = response.headers.get("retry-after")

  if (remaining === "0" && reset) {
    const resetEpoch = Number.parseInt(reset, 10)
    if (Number.isFinite(resetEpoch)) {
      return Math.max(1, resetEpoch - Math.floor(Date.now() / 1000))
    }
  }

  if (retryAfter) {
    const seconds = Number.parseInt(retryAfter, 10)
    if (Number.isFinite(seconds)) return Math.max(1, seconds)
  }

  // 403 without the rate-limit signature is a permission error, not a rate limit
  return null
}

export type SecretFinding = {
  patternId: string
  patternName: string
  severity: SecretPattern["severity"]
  description: string
  filePath: string
  lineNumber: number
  lineContent: string // masked preview
  likelyTestFixture: boolean // true if the file path looks like tests/fixtures/mocks/examples
}

export type ScanResult = {
  repoFullName: string
  scannedAt: string
  filesScanned: number
  filesSkipped: number
  findings: SecretFinding[]
  durationMs: number
  truncated: boolean // true if we hit file count or time limits
}

// File extensions we want to scan (text-based, likely to contain secrets)
const SCANNABLE_EXTENSIONS = new Set([
  "js", "jsx", "ts", "tsx", "mjs", "cjs",
  "py", "rb", "go", "java", "kt", "scala", "rs", "php",
  "c", "cpp", "h", "hpp", "cs",
  "sh", "bash", "zsh", "fish",
  "yml", "yaml", "json", "xml", "toml", "ini", "conf", "config",
  "env", "envrc",
  "md", "txt",
  "sql",
  "dockerfile", "makefile",
  "properties", "plist",
  "tf", "tfvars", // Terraform
  "bicep", // Azure
])

// Heuristics for test/fixture files — findings here are almost always dummy values
const TEST_PATH_PATTERNS: RegExp[] = [
  /(^|\/)(tests?|__tests?__|specs?|fixtures?|mocks?|examples?|samples?|testdata|stubs?|cypress|e2e|demos?)\//i,
  /\.(test|spec)\.[a-z0-9]+$/i, // foo.test.ts, foo.spec.js
  /_test\.[a-z0-9]+$/i, // Go: foo_test.go
  /_spec\.[a-z0-9]+$/i, // Ruby-ish: foo_spec.rb
]

function isTestLikePath(path: string): boolean {
  return TEST_PATH_PATTERNS.some((pattern) => pattern.test(path))
}

// Paths to always skip (vendored code, build output, etc.)
const SKIP_PATH_PATTERNS = [
  /(^|\/)node_modules\//,
  /(^|\/)\.next\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /(^|\/)target\//, // Java/Rust
  /(^|\/)vendor\//,
  /(^|\/)\.git\//,
  /(^|\/)coverage\//,
  /(^|\/)out\//,
  /\.min\.(js|css)$/,
  /\.lock$/,
  /package-lock\.json$/,
  /yarn\.lock$/,
  /pnpm-lock\.yaml$/,
  /\.map$/, // sourcemaps
]

const MAX_FILE_SIZE = 1_000_000 // 1MB
const MAX_FILES_TO_SCAN = 300 // safety limit to avoid huge repos hanging
const MAX_SCAN_TIME_MS = 45_000 // 45s hard cap

type GitHubTreeItem = {
  path: string
  mode: string
  type: "blob" | "tree" | "commit"
  sha: string
  size?: number
  url: string
}

type GitHubTreeResponse = {
  sha: string
  url: string
  tree: GitHubTreeItem[]
  truncated: boolean
}

/**
 * Main scan entry point.
 */
export async function scanRepo(
  accessToken: string | null,
  owner: string,
  repo: string,
  defaultBranch?: string
): Promise<ScanResult> {
  const startedAt = Date.now()
  const repoFullName = `${owner}/${repo}`

  // 1. Resolve branch (use explicit if given, else query repo metadata)
  const branch =
    defaultBranch ?? (await fetchRepoMetadata(accessToken, owner, repo)).default_branch

  // 2. Get the full file tree
  const tree = await fetchRepoTree(accessToken, owner, repo, branch)

  // 3. Filter to scannable files
  const allBlobs = tree.tree.filter((item) => item.type === "blob")
  const scannable = allBlobs.filter((item) => isScannable(item))

  const filesToScan = scannable.slice(0, MAX_FILES_TO_SCAN)
  const filesSkipped = allBlobs.length - filesToScan.length

  // 4. Scan files in parallel batches
  const findings: SecretFinding[] = []
  let filesScanned = 0
  let timeLimitHit = false

  const BATCH_SIZE = 10
  for (let i = 0; i < filesToScan.length; i += BATCH_SIZE) {
    if (Date.now() - startedAt > MAX_SCAN_TIME_MS) {
      timeLimitHit = true
      break
    }

    const batch = filesToScan.slice(i, i + BATCH_SIZE)
    const batchResults = await Promise.all(
      batch.map((file) => scanFile(accessToken, owner, repo, file))
    )

    for (const fileFindings of batchResults) {
      findings.push(...fileFindings)
    }
    filesScanned += batch.length
  }

  return {
    repoFullName,
    scannedAt: new Date().toISOString(),
    filesScanned,
    filesSkipped,
    findings,
    durationMs: Date.now() - startedAt,
    truncated: tree.truncated || timeLimitHit || scannable.length > MAX_FILES_TO_SCAN,
  }
}

async function fetchRepoMetadata(
  accessToken: string | null,
  owner: string,
  repo: string
): Promise<{ default_branch: string }> {
  const url = `https://api.github.com/repos/${owner}/${repo}`
  const response = await fetch(url, {
    headers: buildGitHubHeaders(accessToken),
    cache: "no-store",
  })

  if (response.status === 404) {
    throw new GitHubRepoNotFoundError(owner, repo)
  }
  if (!response.ok) {
    const retryAfter = parseGitHubRateLimit(response)
    if (retryAfter !== null) throw new GitHubRateLimitError(retryAfter)
    throw new Error(`Failed to fetch repo metadata: ${response.status} ${response.statusText}`)
  }

  return response.json()
}

async function fetchRepoTree(
  accessToken: string | null,
  owner: string,
  repo: string,
  branch: string
): Promise<GitHubTreeResponse> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`

  const response = await fetch(url, {
    headers: buildGitHubHeaders(accessToken),
    cache: "no-store",
  })

  if (!response.ok) {
    const retryAfter = parseGitHubRateLimit(response)
    if (retryAfter !== null) {
      throw new GitHubRateLimitError(retryAfter)
    }
    throw new Error(
      `Failed to fetch repo tree: ${response.status} ${response.statusText}`
    )
  }

  return response.json()
}

function isScannable(item: GitHubTreeItem): boolean {
  const path = item.path

  // Skip based on path patterns
  if (SKIP_PATH_PATTERNS.some((pattern) => pattern.test(path))) {
    return false
  }

  // Skip files that are too large
  if (item.size !== undefined && item.size > MAX_FILE_SIZE) {
    return false
  }

  // Check extension
  const lowerPath = path.toLowerCase()
  const lastDot = lowerPath.lastIndexOf(".")
  const fileName = lowerPath.split("/").pop() ?? ""

  // Files with no extension: only scan known names
  if (lastDot === -1 || lastDot < lowerPath.lastIndexOf("/")) {
    return (
      fileName === "dockerfile" ||
      fileName === "makefile" ||
      fileName.startsWith(".env")
    )
  }

  const ext = lowerPath.slice(lastDot + 1)
  return SCANNABLE_EXTENSIONS.has(ext) || fileName.startsWith(".env")
}

async function scanFile(
  accessToken: string | null,
  owner: string,
  repo: string,
  file: GitHubTreeItem
): Promise<SecretFinding[]> {
  try {
    const url = `https://api.github.com/repos/${owner}/${repo}/git/blobs/${file.sha}`
    const response = await fetch(url, {
      headers: buildGitHubHeaders(accessToken),
      cache: "no-store",
    })

    if (!response.ok) return []

    const data = (await response.json()) as { content: string; encoding: string }
    if (data.encoding !== "base64") return []

    const content = Buffer.from(data.content, "base64").toString("utf-8")

    // Skip files that look binary (lots of non-printable chars)
    if (looksBinary(content)) return []

    return matchPatterns(content, file.path)
  } catch {
    return []
  }
}

function looksBinary(content: string): boolean {
  // Sample first 1000 chars; if >10% are non-printable, treat as binary
  const sample = content.slice(0, 1000)
  let nonPrintable = 0
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i)
    if (code === 0 || (code < 32 && code !== 9 && code !== 10 && code !== 13)) {
      nonPrintable++
    }
  }
  return nonPrintable / sample.length > 0.1
}

function matchPatterns(content: string, filePath: string): SecretFinding[] {
  const findings: SecretFinding[] = []
  const lines = content.split("\n")
  const likelyTestFixture = isTestLikePath(filePath)

  for (const pattern of SECRET_PATTERNS) {
    // Reset regex state for global regexes
    pattern.regex.lastIndex = 0

    let match: RegExpExecArray | null
    while ((match = pattern.regex.exec(content)) !== null) {
      const matchIndex = match.index
      const before = content.slice(0, matchIndex)
      const lineNumber = before.split("\n").length
      const lineContent = lines[lineNumber - 1] ?? ""

      findings.push({
        patternId: pattern.id,
        patternName: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        filePath,
        lineNumber,
        lineContent: maskLine(lineContent, match[0]),
        likelyTestFixture,
      })

      // Prevent infinite loops on zero-width matches
      if (match.index === pattern.regex.lastIndex) {
        pattern.regex.lastIndex++
      }
    }
  }

  return findings
}

function maskLine(line: string, matchedText: string): string {
  // Replace the matched secret with ••• for safe display
  const masked = matchedText.length <= 8
    ? "•".repeat(matchedText.length)
    : matchedText.slice(0, 4) + "•".repeat(matchedText.length - 8) + matchedText.slice(-4)

  // Truncate line if too long
  const replaced = line.replace(matchedText, masked)
  return replaced.length > 200 ? replaced.slice(0, 197) + "..." : replaced.trim()
}

function buildGitHubHeaders(accessToken: string | null): HeadersInit {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  }
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`
  }
  return headers
}