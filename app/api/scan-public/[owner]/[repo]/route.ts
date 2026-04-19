import { scanRepo, GitHubRateLimitError, GitHubRepoNotFoundError } from "@/lib/scan"
import { scanDependencies } from "@/lib/deps"
import { NextResponse } from "next/server"

type RouteParams = {
  params: Promise<{
    owner: string
    repo: string
  }>
}

export async function POST(
  request: Request,
  { params }: RouteParams
) {
  // 1. Extract route params
  const { owner, repo } = await params

  // 2. Optional: read explicit branch from body (otherwise we auto-detect)
  let explicitBranch: string | undefined
  try {
    const body = await request.json()
    if (typeof body?.defaultBranch === "string" && body.defaultBranch.length > 0) {
      explicitBranch = body.defaultBranch
    }
  } catch {
    // No body or invalid JSON — leave undefined so scanRepo auto-detects
  }

  // 3. Run both scans in parallel WITHOUT auth token (public API rate limits apply: 60/h per IP)
  try {
    const [secretsResult, dependencies] = await Promise.all([
      scanRepo(null, owner, repo, explicitBranch),
      scanDependencies(owner, repo, null),
    ])

    const fullResult = {
      ...secretsResult,
      dependencies,
    }

    return NextResponse.json(fullResult)
  } catch (error) {
    if (error instanceof GitHubRateLimitError) {
      return NextResponse.json(
        {
          error: "GitHub API rate limit exceeded for anonymous scans.",
          retryAfterSeconds: error.retryAfterSeconds,
        },
        {
          status: 429,
          headers: { "Retry-After": String(error.retryAfterSeconds) },
        }
      )
    }
    if (error instanceof GitHubRepoNotFoundError) {
      return NextResponse.json(
        { error: `Repository ${error.owner}/${error.repo} not found. It may be private or not exist.` },
        { status: 404 }
      )
    }
    const message = error instanceof Error ? error.message : "Unknown error"
    return NextResponse.json(
      { error: `Scan failed: ${message}` },
      { status: 500 }
    )
  }
}

// Also allow GET for convenience during development / manual testing
export async function GET(
  request: Request,
  routeCtx: RouteParams
) {
  return POST(request, routeCtx)
}