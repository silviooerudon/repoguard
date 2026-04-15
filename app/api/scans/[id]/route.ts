import { auth } from "@/auth"
import { supabase } from "@/lib/supabase"
import { NextResponse } from "next/server"

type RouteParams = {
  params: Promise<{ id: string }>
}

export async function GET(_request: Request, { params }: RouteParams) {
  // 1. Authentication
  const session = await auth()
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const userId = session.user?.name ?? session.user?.email ?? "unknown"
  const { id } = await params

  // 2. Fetch scan from DB
  const { data, error } = await supabase
    .from("scans")
    .select("id, owner, repo, scanned_at, result, duration_ms, files_scanned, secrets_count, deps_count, user_id")
    .eq("id", id)
    .single()

  if (error || !data) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 })
  }

  // 3. Authorization: user can only see own scans
  if (data.user_id !== userId) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 })
  }

  // 4. Return without leaking user_id
  const { user_id: _, ...safeScan } = data
  return NextResponse.json({ scan: safeScan })
}