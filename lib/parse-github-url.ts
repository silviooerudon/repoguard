export type ParsedRepo = {
  owner: string
  repo: string
}

/**
 * Parses common GitHub URL formats and returns owner/repo.
 * Returns null if the input is not a valid GitHub repo URL.
 *
 * Accepted formats:
 *   https://github.com/owner/repo
 *   https://github.com/owner/repo.git
 *   https://github.com/owner/repo/tree/main
 *   http://github.com/owner/repo
 *   github.com/owner/repo  (no protocol)
 */
export function parseGitHubUrl(input: string): ParsedRepo | null {
  if (!input || typeof input !== "string") return null

  const trimmed = input.trim()
  if (!trimmed) return null

  // Add protocol if missing so URL constructor works
  const withProtocol = /^https?:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`

  let url: URL
  try {
    url = new URL(withProtocol)
  } catch {
    return null
  }

  if (url.hostname.toLowerCase() !== "github.com") return null

  // Split path: /owner/repo/...  -> ["", "owner", "repo", ...]
  const parts = url.pathname.split("/").filter(Boolean)
  if (parts.length < 2) return null

  const owner = parts[0]
  let repo = parts[1]

  // Strip .git suffix
  if (repo.endsWith(".git")) {
    repo = repo.slice(0, -4)
  }

  // Basic sanity: GitHub usernames/repo names allow [A-Za-z0-9._-]
  const validName = /^[A-Za-z0-9._-]+$/
  if (!validName.test(owner) || !validName.test(repo)) return null

  return { owner, repo }
}