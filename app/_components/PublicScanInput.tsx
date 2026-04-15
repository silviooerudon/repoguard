"use client"

import { useRouter } from "next/navigation"
import { useState } from "react"
import { parseGitHubUrl } from "@/lib/parse-github-url"

export default function PublicScanInput() {
  const router = useRouter()
  const [input, setInput] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  function handleScan() {
    setError(null)
    const parsed = parseGitHubUrl(input)
    if (!parsed) {
      setError("Please enter a valid GitHub repo URL (e.g. https://github.com/owner/repo)")
      return
    }
    setLoading(true)
    router.push(`/scan-public/${parsed.owner}/${parsed.repo}`)
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      handleScan()
    }
  }

  return (
    <div className="max-w-xl mx-auto mb-6">
      <div className="flex flex-col sm:flex-row gap-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="https://github.com/owner/repo"
          className="flex-1 px-4 py-3 rounded-lg bg-slate-900 border border-slate-800 text-slate-100 placeholder-slate-600 focus:outline-none focus:border-blue-500 transition"
          disabled={loading}
        />
        <button
          type="button"
          onClick={handleScan}
          disabled={loading || !input.trim()}
          className="px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 disabled:cursor-not-allowed transition text-white font-medium"
        >
          {loading ? "Loading…" : "Scan public repo"}
        </button>
      </div>
      {error && (
        <p className="text-red-400 text-xs mt-2 text-left">{error}</p>
      )}
      <p className="text-xs text-slate-500 mt-3">
        No login required for public repos. 60 scans per hour shared limit.
      </p>
    </div>
  )
}