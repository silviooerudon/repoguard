# Plan: Unified Risk Score & Prioritization

**Status:** Planned · **Sessions:** 2 · **Decided:** 2026-04-30

## Why this exists

Today RepoGuard returns 7 independent finding lists. A real repo scan returns 50-200 findings with no priority. Users either skim the top and miss what matters, or get overwhelmed and abandon the tool.

A unified score solves three problems at once:
1. **Headline number** - "your repo: 73/100 risk" is screenshot-able, shareable
2. **Final ordering** - every finding compared on one axis, regardless of detector
3. **Foundation for diffing** - score delta between scans = clear "got better/worse"

## Design decisions (do not re-debate without explicit reason)

- **Scale:** 0-100, high = dangerous (CVSS-like). Matches industry convention. Posture Score (Bloco 2) will invert this to high=healthy, which is intentional separation.
- **Formula:** weighted sum by severity (simple, transparent, debuggable).
- **Test/fixture findings:** included at 10% weight (not excluded).
- **Per-finding score:** every finding gets its own score so the UI can sort by it, not just by severity bucket.

## Severity weights (base points per finding)

| Severity | Base points |
|---|---|
| critical | 40 |
| high | 15 |
| medium | 5 |
| low | 1 |
| moderate (deps only) | 5 - alias to medium |

Rationale: critical findings should dominate. One critical secret is worse than ten medium SAST hits, and the math reflects that.

## Modifiers (applied per finding)

| Modifier | Multiplier | Where |
|---|---|---|
| likelyTestFixture: true | x 0.1 | secrets, code, sensitive-files |
| isTransitive: true (dep) | x 0.5 | dependencies (you can not fix it directly) |
| source: "history" | x 0.5 | secrets - already removed from tree, still rotatable |
| Sensitive file detected by name only | x 1.0 | no modifier - name-based is high signal |

## Aggregation

repoScore = min(100, sum of (basePoints[severity] x modifier) for all findings)

Capped at 100. A repo with 30 critical secrets and a clean repo with 3 critical secrets both score 100 - that is intentional. Once you are at "this repo is on fire", the exact temperature does not matter.

## Per-finding score

findingScore = basePoints[severity] x modifier

Range: 0.1 (test-fixture low) to 40 (untouched critical). Sort descending.

## What ships in Session 1 (backend)

1. New lib/risk.ts exporting scoreFinding, scoreRepo, prioritize.
2. Wire into both routes (/api/scan/... and /api/scan-public/...). Add fields: riskScore (0-100), riskBreakdown ({critical, high, medium, low, fixture}), prioritized (PrioritizedFinding array).
3. Persist riskScore as a column on scans table (Supabase migration). Enables diffing in a later session without rescanning.
4. Backward compat: existing fields (findings, dependencies, etc.) stay untouched. UI keeps working. New fields are additive.

## What ships in Session 2 (frontend)

- Score badge at top of scan results page
- Sort findings tab by findingScore (default), with toggle for "by detector"
- Score breakdown ("40 from critical secrets, 15 from high deps, ...")
- Defer: history chart of repo score over time (waits for diffing feature)

## Out of scope (deferred to later blocks)

- Exploitability scoring (would require runtime context)
- "Public-facing route" weighting (needs framework awareness - Camada 3)
- Per-detector custom weights via config
- User-tunable severity thresholds

## Open questions (decide before Session 2 starts)

- How does riskScore interact with truncated: true scans? Show with warning "incomplete scan" or hide? Lean: show with warning.
- Should score include iacFindings from npm lifecycle scripts at full weight? Lean: yes - curl|sh in postinstall is genuinely critical.
