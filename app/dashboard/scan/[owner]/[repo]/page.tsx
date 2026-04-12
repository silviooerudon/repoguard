"use client"

import { useEffect, useState, use } from "react"
import type { ScanResult, SecretFinding } from "@/lib/scan"

type PageProps = {
  params: Promise<{
    owner: string
    repo: string
  }>
  searchParams: Promise<{
    branch?: string
  }>
}

export default function ScanPage({ params, searchParams }: PageProps) {
  const { owner, repo } = use(params)
  const { branch } = use(searchParams)

  const [status, setStatus] = useState<"running" | "done" | "error">("running")
  const [result, setResult] = useState<ScanResult | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()

    async function runScan() {
      try {
        const response = await fetch(`/api/scan/${owner}/${repo}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ defaultBranch: branch ?? "main" }),
          signal: controller.signal,
        })

        if (!response.ok) {
          const errorBody = await response.json().catch(() => ({}))
          throw new Error(errorBody.error ?? `Scan failed (${response.status})`)
        }

        const data: ScanResult = await response.json()
        setResult(data)
        setStatus("done")
      } catch (err) {
        if (err instanceof Error && err.name === "AbortError") return
        setErrorMessage(err instanceof Error ? err.message : "Unknown error")
        setStatus("error")
      }
    }

    runScan()
    return () => controller.abort()
  }, [owner, repo, branch])

  return (
    <main className="min-h-screen bg-gradient-to-b from-gray-950 to-gray-900 text-white px-6 py-12">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-10">
            <a
          
            href="/dashboard"
            className="text-gray-400 hover:text-white text-sm flex items-center gap-1 transition"
          >
            ← Back to repositories
          </a>
        </div>

        <h1 className="text-3xl font-bold mb-2">
          Scanning{" "}
          <span className="text-blue-400">
            {owner}/{repo}
          </span>
        </h1>
        <p className="text-gray-400 text-sm mb-8">
          Looking for exposed secrets in the default branch
          {branch ? ` (${branch})` : ""}.
        </p>

        {/* Running state */}
        {status === "running" && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
            <div className="inline-block w-8 h-8 border-4 border-blue-500/30 border-t-blue-500 rounded-full animate-spin mb-4" />
            <p className="text-gray-300">Scanning repository…</p>
            <p className="text-gray-500 text-sm mt-2">
              This usually takes a few seconds.
            </p>
          </div>
        )}

        {/* Error state */}
        {status === "error" && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6">
            <p className="text-red-400 font-semibold mb-1">⚠️ Scan failed</p>
            <p className="text-red-300/80 text-sm">{errorMessage}</p>
          </div>
        )}

        {/* Results */}
        {status === "done" && result && (
          <ScanResultView result={result} />
        )}
      </div>
    </main>
  )
}

function ScanResultView({ result }: { result: ScanResult }) {
  const { findings, filesScanned, filesSkipped, durationMs, truncated } = result

  const critical = findings.filter((f) => f.severity === "critical").length
  const high = findings.filter((f) => f.severity === "high").length
  const medium = findings.filter((f) => f.severity === "medium").length

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <SummaryCard
          label="Files scanned"
          value={filesScanned.toString()}
          tone="neutral"
        />
        <SummaryCard
          label="Critical"
          value={critical.toString()}
          tone={critical > 0 ? "red" : "neutral"}
        />
        <SummaryCard
          label="High"
          value={high.toString()}
          tone={high > 0 ? "orange" : "neutral"}
        />
        <SummaryCard
          label="Medium"
          value={medium.toString()}
          tone={medium > 0 ? "yellow" : "neutral"}
        />
      </div>

      <p className="text-xs text-gray-500">
        Scan took {(durationMs / 1000).toFixed(2)}s • {filesSkipped} files skipped
        {truncated && " • results truncated (repo too large)"}
      </p>

      {/* All clear */}
      {findings.length === 0 && (
        <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-8 text-center">
          <p className="text-5xl mb-3">✅</p>
          <h2 className="text-xl font-semibold text-green-400 mb-2">
            No secrets found
          </h2>
          <p className="text-gray-400 text-sm max-w-md mx-auto">
            We scanned your code for common secret patterns and found nothing
            exposed. Good job!
          </p>
        </div>
      )}

      {/* Findings list */}
      {findings.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-xl font-semibold">
            {findings.length} potential{" "}
            {findings.length === 1 ? "secret" : "secrets"} found
          </h2>
          {findings.map((finding, i) => (
            <FindingCard key={i} finding={finding} />
          ))}
        </div>
      )}
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
  const severityConfig = {
    critical: {
      label: "Critical",
      badge: "bg-red-500/10 border-red-500/20 text-red-400",
    },
    high: {
      label: "High",
      badge: "bg-orange-500/10 border-orange-500/20 text-orange-400",
    },
    medium: {
      label: "Medium",
      badge: "bg-yellow-500/10 border-yellow-500/20 text-yellow-400",
    },
  }

  const config = severityConfig[finding.severity]

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-start justify-between gap-4 mb-3 flex-wrap">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <h3 className="font-semibold">{finding.patternName}</h3>
            <span
              className={`text-xs px-2 py-0.5 rounded-full border ${config.badge}`}
            >
              {config.label}
            </span>
          </div>
          <p className="text-sm text-gray-400">{finding.description}</p>
        </div>
      </div>

      <div className="font-mono text-xs bg-black/40 border border-gray-800 rounded-lg p-3 overflow-x-auto">
        <div className="text-gray-500 mb-1">
          {finding.filePath}:{finding.lineNumber}
        </div>
        <div className="text-gray-300 whitespace-pre">
          {finding.lineContent}
        </div>
      </div>
    </div>
  )
}