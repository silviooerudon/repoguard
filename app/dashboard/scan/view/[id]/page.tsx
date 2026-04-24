"use client"

import { useEffect, useState, use } from "react"
import Link from "next/link"
import type { ScanResult, SecretFinding } from "@/lib/scan"
import type { DependencyFinding } from "@/lib/types"

type ScanResultWithDeps = ScanResult & { dependencies: DependencyFinding[] }

type SavedScan = {
  id: string
  owner: string
  repo: string
  scanned_at: string
  result: ScanResultWithDeps
  duration_ms: number
  files_scanned: number
  secrets_count: number
  deps_count: number
}

type PageProps = {
  params: Promise<{ id: string }>
}

export default function ScanViewPage({ params }: PageProps) {
  const { id } = use(params)

  const [status, setStatus] = useState<"loading" | "done" | "error">("loading")
  const [scan, setScan] = useState<SavedScan | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  useEffect(() => {
    async function fetchScan() {
      try {
        const res = await fetch(`/api/scans/${id}`)
        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.error ?? `Failed (${res.status})`)
        }
        const data = await res.json()
        setScan(data.scan)
        setStatus("done")
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : "Unknown error")
        setStatus("error")
      }
    }
    fetchScan()
  }, [id])

  return (
    <main className="min-h-screen bg-gradient-to-b from-gray-950 to-gray-900 text-white px-6 py-12">
      <div className="max-w-5xl mx-auto">
        <div className="flex items-center justify-between mb-10">
          <Link
            href="/dashboard/history"
            className="text-gray-400 hover:text-white text-sm flex items-center gap-1 transition"
          >
            ← Back to history
          </Link>
        </div>

        {status === "loading" && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
            <div className="inline-block w-8 h-8 border-4 border-blue-500/30 border-t-blue-500 rounded-full animate-spin mb-4" />
            <p className="text-gray-300">Loading scan…</p>
          </div>
        )}

        {status === "error" && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6">
            <p className="text-red-400 font-semibold mb-1">⚠️ Failed to load</p>
            <p className="text-red-300/80 text-sm">{errorMessage}</p>
          </div>
        )}

        {status === "done" && scan && <SavedScanView scan={scan} />}
      </div>
    </main>
  )
}

function SavedScanView({ scan }: { scan: SavedScan }) {
  const dateStr = new Date(scan.scanned_at).toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })

  const findings = scan.result.findings ?? []
  const dependencies = scan.result.dependencies ?? []

  const sourceFindings = findings.filter((f) => !f.likelyTestFixture)
  const testFixtureCount = findings.length - sourceFindings.length
  const sortedFindings = [...findings].sort(
    (a, b) => Number(a.likelyTestFixture ?? false) - Number(b.likelyTestFixture ?? false)
  )

  const critical = sourceFindings.filter((f) => f.severity === "critical").length
  const high = sourceFindings.filter((f) => f.severity === "high").length
  const medium = sourceFindings.filter((f) => f.severity === "medium").length

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold mb-2">
          <span className="text-blue-400 font-mono">
            {scan.owner}/{scan.repo}
          </span>
        </h1>
        <p className="text-gray-400 text-sm">
          Scanned on {dateStr} • {scan.files_scanned} files • {(scan.duration_ms / 1000).toFixed(2)}s
          {testFixtureCount > 0 && ` • ${testFixtureCount} match${testFixtureCount === 1 ? "" : "es"} in test files (shown below, not counted above)`}
        </p>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <SummaryCard label="Files scanned" value={scan.files_scanned.toString()} tone="neutral" />
        <SummaryCard label="Critical" value={critical.toString()} tone={critical > 0 ? "red" : "neutral"} />
        <SummaryCard label="High" value={high.toString()} tone={high > 0 ? "orange" : "neutral"} />
        <SummaryCard label="Medium" value={medium.toString()} tone={medium > 0 ? "yellow" : "neutral"} />
      </div>

      {findings.length === 0 && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-8 text-center">
          <p className="text-5xl mb-3">✅</p>
          <h2 className="text-xl font-semibold text-green-400 mb-2">No secrets found</h2>
          <p className="text-gray-400 text-sm">No secret patterns matched in this scan.</p>
        </div>
      )}

      {findings.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-xl font-semibold">
            {findings.length} {findings.length === 1 ? "secret" : "secrets"} found
          </h2>
          {sortedFindings.map((finding, i) => (
            <FindingCard key={i} finding={finding} />
          ))}
        </div>
      )}

      <DependenciesSection dependencies={dependencies} />
    </div>
  )
}

function SummaryCard({
  label,
  value,
  tone,
}: {
  label: string
  value: string
  tone: "neutral" | "red" | "orange" | "yellow"
}) {
  const colors: Record<typeof tone, string> = {
    neutral: "bg-gray-900 border-gray-800 text-gray-300",
    red: "bg-red-500/10 border-red-500/20 text-red-400",
    orange: "bg-orange-500/10 border-orange-500/20 text-orange-400",
    yellow: "bg-yellow-500/10 border-yellow-500/20 text-yellow-400",
  }
  return (
    <div className={`rounded-xl border p-4 ${colors[tone]}`}>
      <div className="text-xs uppercase tracking-wider opacity-70">{label}</div>
      <div className="text-2xl font-bold mt-1">{value}</div>
    </div>
  )
}

function FindingCard({ finding }: { finding: SecretFinding }) {
  const config = {
    critical: { label: "Critical", badge: "bg-red-500/10 border-red-500/20 text-red-400" },
    high: { label: "High", badge: "bg-orange-500/10 border-orange-500/20 text-orange-400" },
    medium: { label: "Medium", badge: "bg-yellow-500/10 border-yellow-500/20 text-yellow-400" },
    low: { label: "Low", badge: "bg-gray-500/10 border-gray-500/30 text-gray-400" },
  }[finding.severity]

  const isTest = finding.likelyTestFixture ?? false

  return (
    <div
      className={`bg-gray-900 border border-gray-800 rounded-xl p-5 ${
        isTest ? "opacity-60" : ""
      }`}
    >
      <div className="flex items-center gap-2 flex-wrap mb-1">
        <h3 className="font-semibold">{finding.patternName}</h3>
        <span className={`text-xs px-2 py-0.5 rounded-full border ${config.badge}`}>{config.label}</span>
        {isTest && (
          <span
            className="text-xs px-2 py-0.5 rounded-full border bg-gray-500/10 border-gray-500/30 text-gray-400"
            title="Found in a test/fixture/mock/example path — likely a dummy value"
          >
            Test fixture
          </span>
        )}
      </div>
      <p className="text-sm text-gray-400 mb-3">{finding.description}</p>
      <div className="font-mono text-xs bg-black/40 border border-gray-800 rounded-lg p-3 overflow-x-auto">
        <div className="text-gray-500 mb-1">{finding.filePath}:{finding.lineNumber}</div>
        <div className="text-gray-300 whitespace-pre">{finding.lineContent}</div>
      </div>
    </div>
  )
}

function DependenciesSection({ dependencies }: { dependencies: DependencyFinding[] }) {
  if (dependencies.length === 0) {
    return (
      <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-6 text-center">
        <p className="text-2xl mb-2">📦</p>
        <h2 className="text-lg font-semibold text-green-400 mb-1">No vulnerable dependencies</h2>
        <p className="text-gray-400 text-sm">No known CVEs in package.json dependencies.</p>
      </div>
    )
  }

  return (
    <div className="space-y-3 pt-4">
      <h2 className="text-xl font-semibold">
        {dependencies.length} vulnerable {dependencies.length === 1 ? "dependency" : "dependencies"} found
      </h2>
      {dependencies.map((dep, i) => (
        <DependencyCard key={i} dep={dep} />
      ))}
    </div>
  )
}

function DependencyCard({ dep }: { dep: DependencyFinding }) {
  const config: Record<DependencyFinding["severity"], { label: string; badge: string }> = {
    critical: { label: "Critical", badge: "bg-red-500/10 border-red-500/20 text-red-400" },
    high: { label: "High", badge: "bg-orange-500/10 border-orange-500/20 text-orange-400" },
    moderate: { label: "Moderate", badge: "bg-yellow-500/10 border-yellow-500/20 text-yellow-400" },
    low: { label: "Low", badge: "bg-gray-500/10 border-gray-500/20 text-gray-400" },
  }
  const c = config[dep.severity]

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-center gap-2 flex-wrap mb-1">
        <h3 className="font-semibold font-mono">{dep.package}@{dep.version}</h3>
        <span className={`text-xs px-2 py-0.5 rounded-full border ${c.badge}`}>{c.label}</span>
      </div>
      <p className="text-sm text-gray-400 mb-3">{dep.title}</p>
      <div className="text-xs space-y-1 bg-black/40 border border-gray-800 rounded-lg p-3">
        {dep.ghsa && (
          <div className="text-gray-400">
            <span className="text-gray-500">Advisory:</span>{" "}
            <span className="font-mono">{dep.ghsa}</span>
          </div>
        )}
        <div className="text-gray-400">
          <span className="text-gray-500">Vulnerable versions:</span>{" "}
          <span className="font-mono text-red-400">{dep.vulnerable_versions}</span>
        </div>
        {dep.cvss_score !== null && (
          <div className="text-gray-400">
            <span className="text-gray-500">CVSS score:</span>{" "}
            <span className="font-mono">{dep.cvss_score}</span>
          </div>
        )}
        <a
          href={dep.url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-block text-blue-400 hover:underline mt-1"
        >
          View advisory →
        </a>
      </div>
    </div>
  )
}