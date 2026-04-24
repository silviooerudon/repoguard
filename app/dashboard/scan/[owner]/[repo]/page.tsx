"use client"

import { useEffect, useState, use } from "react"
import type { ScanResult } from "@/lib/scan"
import type { DependencyFinding } from "@/lib/types"
import {
  AllClear,
  CodeFindingsSection,
  DependenciesSection,
  IaCFindingsSection,
  SecretsSection,
  SensitiveFilesSection,
  SummaryCard,
  countBySeverity,
  totalCount,
  type AllFindings,
} from "@/app/components/scan-findings"

type ScanResultFull = ScanResult & {
  dependencies?: DependencyFinding[]
  pythonDependencies?: DependencyFinding[]
}

type PageProps = {
  params: Promise<{ owner: string; repo: string }>
  searchParams: Promise<{ branch?: string }>
}

export default function ScanPage({ params, searchParams }: PageProps) {
  const { owner, repo } = use(params)
  const { branch } = use(searchParams)

  const [status, setStatus] = useState<"running" | "done" | "error">("running")
  const [result, setResult] = useState<ScanResultFull | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    async function runScan() {
      try {
        const response = await fetch(`/api/scan/${owner}/${repo}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(branch ? { defaultBranch: branch } : {}),
          signal: controller.signal,
        })
        if (!response.ok) {
          const errorBody = await response.json().catch(() => ({}))
          throw new Error(errorBody.error ?? `Scan failed (${response.status})`)
        }
        const data: ScanResultFull = await response.json()
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
          Secrets, dependencies, code vulnerabilities, CI/IaC configuration and
          git history{branch ? ` (branch ${branch})` : ""}.
        </p>

        {status === "running" && (
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-8 text-center">
            <div className="inline-block w-8 h-8 border-4 border-blue-500/30 border-t-blue-500 rounded-full animate-spin mb-4" />
            <p className="text-gray-300">Scanning repository…</p>
            <p className="text-gray-500 text-sm mt-2">
              Seven detectors running in parallel — usually under a minute.
            </p>
          </div>
        )}

        {status === "error" && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6">
            <p className="text-red-400 font-semibold mb-1">⚠️ Scan failed</p>
            <p className="text-red-300/80 text-sm">{errorMessage}</p>
          </div>
        )}

        {status === "done" && result && <ScanResultView result={result} />}
      </div>
    </main>
  )
}

function ScanResultView({ result }: { result: ScanResultFull }) {
  const all: AllFindings = {
    secrets: (result.findings ?? []).filter(
      (f) => !f.source || f.source === "tree",
    ),
    historySecrets: result.historyFindings ?? [],
    sensitiveFiles: result.sensitiveFiles ?? [],
    codeFindings: result.codeFindings ?? [],
    iacFindings: result.iacFindings ?? [],
    npmDependencies: result.dependencies ?? [],
    pythonDependencies: result.pythonDependencies ?? [],
  }

  const counts = countBySeverity(all)
  const total = totalCount(all)

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <SummaryCard
          label="Files scanned"
          value={result.filesScanned.toString()}
          tone="neutral"
        />
        <SummaryCard
          label="Critical"
          value={counts.critical.toString()}
          tone={counts.critical > 0 ? "red" : "neutral"}
        />
        <SummaryCard
          label="High"
          value={counts.high.toString()}
          tone={counts.high > 0 ? "orange" : "neutral"}
        />
        <SummaryCard
          label="Medium + Low"
          value={(counts.medium + counts.low).toString()}
          tone={counts.medium + counts.low > 0 ? "yellow" : "neutral"}
        />
      </div>

      <p className="text-xs text-gray-500">
        Scan took {(result.durationMs / 1000).toFixed(2)}s •{" "}
        {result.filesSkipped} files skipped
        {result.truncated && " • results truncated (repo too large)"}
      </p>

      {total === 0 && <AllClear />}

      <SecretsSection findings={all.secrets} sourceLabel="tree" />
      <SensitiveFilesSection findings={all.sensitiveFiles} />
      <CodeFindingsSection findings={all.codeFindings} />
      <DependenciesSection findings={all.npmDependencies} label="npm" />
      <DependenciesSection findings={all.pythonDependencies} label="Python" />
      <IaCFindingsSection findings={all.iacFindings} />
      <SecretsSection findings={all.historySecrets} sourceLabel="history" />
    </div>
  )
}
