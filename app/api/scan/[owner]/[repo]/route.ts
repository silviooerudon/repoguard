import { auth } from "@/auth"
import { scanRepo, GitHubRateLimitError, GitHubRepoNotFoundError } from "@/lib/scan"
import { scanDependencies } from "@/lib/deps"
import { scanPythonDependencies } from "@/lib/python-deps"
import { supabase } from "@/lib/supabase"
import { flattenScan, scoreRepo } from "@/lib/risk"
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
  const session = await auth()
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  // @ts-expect-error - accessToken custom field
  const accessToken = session.accessToken as string | undefined
  if (!accessToken) {
    return NextResponse.json(
      { error: "No access token available. Please sign in again." },
      { status: 401 },
    )
  }

  const { owner, repo } = await params

  let explicitBranch: string | undefined
  try {
    const body = await request.json()
    if (typeof body?.defaultBranch === "string" && body.defaultBranch.length > 0) {
      explicitBranch = body.defaultBranch
    }
  } catch {
    // no body — scanRepo auto-detects
  }

  try {
    const [secretsResult, npmResult, pythonDeps] = await Promise.all([
      scanRepo(accessToken, owner, repo, explicitBranch),
      scanDependencies(owner, repo, accessToken),
      scanPythonDependencies(owner, repo, accessToken),
    ])

    const fullResult = {
      ...secretsResult,
      dependencies: npmResult.vulns,
      pythonDependencies: pythonDeps,
      iacFindings: [
        ...(secretsResult.iacFindings ?? []),
        ...npmResult.lifecycleIssues,
      ],
    }

    const assessment = scoreRepo(flattenScan(fullResult))

    const userId = session.user?.name ?? session.user?.email ?? "unknown"
    const { error: dbError } = await supabase.from("scans").insert({
      user_id: userId,
      owner,
      repo,
      result: fullResult,
      duration_ms: secretsResult.durationMs,
      files_scanned: secretsResult.filesScanned,
      secrets_count: secretsResult.findings.length,
      deps_count: npmResult.vulns.length + pythonDeps.length,
      risk_score: assessment.score,
    })

    if (dbError) {
      console.error("[scan] Failed to persist scan:", dbError.message)
    }

    return NextResponse.json({
      ...fullResult,
      riskScore: assessment.score,
      riskBreakdown: assessment.breakdown,
      prioritized: assessment.prioritized,
    })
  } catch (error) {
    if (error instanceof GitHubRateLimitError) {
      return NextResponse.json(
        {
          error: "GitHub API rate limit exceeded.",
          retryAfterSeconds: error.retryAfterSeconds,
        },
        {
          status: 429,
          headers: { "Retry-After": String(error.retryAfterSeconds) },
        },
      )
    }
    if (error instanceof GitHubRepoNotFoundError) {
      return NextResponse.json(
        { error: `Repository ${error.owner}/${error.repo} not found or inaccessible.` },
        { status: 404 },
      )
    }
    const message = error instanceof Error ? error.message : "Unknown error"
    return NextResponse.json({ error: `Scan failed: ${message}` }, { status: 500 })
  }
}

export async function GET(
  request: Request,
  routeCtx: RouteParams,
) {
  return POST(request, routeCtx)
}
