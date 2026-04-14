import { auth } from "@/auth"
import { scanRepo } from "@/lib/scan"
import { scanDependencies } from "@/lib/deps"
import { supabase } from "@/lib/supabase"
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
  // 1. Check authentication
  const session = await auth()
  if (!session) {
    return NextResponse.json(
      { error: "Unauthorized" },
      { status: 401 }
    )
  }

  // @ts-expect-error - accessToken custom field
  const accessToken = session.accessToken as string | undefined
  if (!accessToken) {
    return NextResponse.json(
      { error: "No access token available. Please sign in again." },
      { status: 401 }
    )
  }

  // 2. Extract route params
  const { owner, repo } = await params

  // 3. Optional: read default branch from body (sent by the dashboard)
  let defaultBranch = "main"
  try {
    const body = await request.json()
    if (typeof body?.defaultBranch === "string" && body.defaultBranch.length > 0) {
      defaultBranch = body.defaultBranch
    }
  } catch {
    // No body or invalid JSON — fall back to "main"
  }

  // 4. Run both scans in parallel
  try {
    const [secretsResult, dependencies] = await Promise.all([
      scanRepo(accessToken, owner, repo, defaultBranch),
      scanDependencies(owner, repo, accessToken),
    ])

    const fullResult = {
      ...secretsResult,
      dependencies,
    }

    // 5. Persist scan to Supabase (non-blocking for user response)
    const userId = session.user?.name ?? session.user?.email ?? "unknown"
    const { error: dbError } = await supabase.from("scans").insert({
      user_id: userId,
      owner,
      repo,
      result: fullResult,
      duration_ms: secretsResult.durationMs,
      files_scanned: secretsResult.filesScanned,
      secrets_count: secretsResult.findings.length,
      deps_count: dependencies.length,
    })

    if (dbError) {
      console.error("[scan] Failed to persist scan:", dbError.message)
      // Não falha a resposta pro usuário — scan funcionou, só a persistência falhou
    }

    return NextResponse.json(fullResult)
  } catch (error) {
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