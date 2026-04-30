Plan: Suppressions via .repoguardignore (Bloco 1, item 3)
Status: Planned · Sessions: 2 (A: backend, B: UI) · Decided: 2026-04-30
Why this exists
Today every scan is unfiltered. First scan in a real repo returns 50-200 findings, including known/accepted ones (test fixtures, intentional examples, tracked tech debt). Without suppression, users abandon RepoGuard after one scan because the list never shrinks.
Suppressions transform RepoGuard from "shows problems" into "shows problems that matter to YOU".
Design decisions (do not re-debate)
Where to define

Single file: .repoguardignore at repo root
Plain text, line-based (like .gitignore)
Versioned with the code, reviewed in PRs
Same mechanism for authenticated and anonymous scans
Rejected: YAML config (overkill), inline comments (fragile), UI-only/Supabase (invisible to team)

Behavior when suppressed

Suppressed findings DO NOT contribute to riskScore or riskBreakdown
Suppressed findings DO NOT appear in prioritized list
Suppressed findings DO appear in a separate suppressed array on the response
UI shows a collapsed "Suppressed (N)" section, expandable to audit
Rejected: silent removal (dishonest), opacity-dim in main list (defeats purpose)

Granularity

Path glob (always required) + optional rule glob + optional reason + optional expires date
Precedence: more specific rule wins over wildcard
Glob library: minimatch (battle-tested, small, no transitive deps)
Rejected: path-only (too broad), reason-mandatory (devs write "lol")

Expiration

Optional ISO date expires=YYYY-MM-DD
When expired, the suppression is IGNORED (finding surfaces as if unsuppressed) AND a warning surfaces in the response
UI shows "N expired suppressions — review" alert at top
Rejected: no-expiration (creates permanent debt), mandatory (friction)

File format
Format per line: <path-glob> [rule-id-or-glob] [reason="..."] [expires=YYYY-MM-DD]. Comments start with #. Blank lines ignored. Order does not matter.
Examples:

tests/fixtures/** — path only, suppresses all findings in this glob
docs/security-examples/** secret/aws-access-key — path + specific rule
examples/** sast/* reason="Educational examples" — path + rule wildcard + reason
src/legacy/auth.ts sast/sql-injection reason="JIRA-1234" expires=2026-09-30 — full form

Rule ID format
Existing detectors already produce stable IDs. Suppressions match against:

Secrets: secret/<patternId> (from SECRET_PATTERNS, e.g. secret/aws-access-key)
Code: code/<ruleId> (from CODE_RULES, e.g. code/js-ssrf-fetch-user-input)
IaC: iac/<ruleId> (from DOCKER_RULES/ACTIONS_RULES, e.g. iac/dockerfile-user-root)
Sensitive files: sensitive-file/<kind> (e.g. sensitive-file/private-key)
Dependencies: dependency/<ghsa> or dependency/<package> (e.g. dependency/lodash or dependency/GHSA-xxxx)

Wildcards: secret/*, * (everything).
Architecture
New file: lib/suppressions.ts
Exports:

parseSuppressions(content: string): Suppression[] — line parser
findRuleIdForFinding(finding: AnyFinding): string — build the rule-id string
applySuppressions(findings: AnyFinding[], suppressions: Suppression[]): { active: AnyFinding[], suppressed: SuppressedFinding[], expiredCount: number }
Type Suppression { pathGlob, ruleGlob?, reason?, expires?, raw, lineNumber }
Type SuppressedFinding = AnyFinding & { suppression: Suppression, isExpired: boolean }

Integration

scanRepo (in lib/scan.ts) fetches .repoguardignore from repo root in parallel with the tree fetch. If absent → empty suppressions list. If 404 → empty (not error).
Both routes call applySuppressions(flattenScan(fullResult), suppressions) BEFORE scoreRepo.
Response shape adds two fields: suppressed: SuppressedFinding[] and expiredSuppressionsCount: number.
scoreRepo(active) uses ONLY active findings — score reflects what users see.

Backward compat

Repos without .repoguardignore behave identically to today
Old persisted scans without suppressed/expiredSuppressionsCount fields render fine (UI treats undefined as empty)

Sessions
Session A (backend) — this plan

Create lib/suppressions.ts with parser + matcher
Install minimatch as runtime dep
Fetch .repoguardignore from GitHub API (best-effort, soft-fail)
Wire into both routes BEFORE scoring
Smoke test against juice-shop with a synthetic .repoguardignore

Session B (UI)

Add SuppressedSection collapsed by default with count
Add ExpiredAlert banner at top when expiredSuppressionsCount > 0
Each suppressed finding shows: original card + footer with "Suppressed by: <line> — <reason>" and "Expires: <date>" if set
Both pages updated

Out of scope (deferred)

UI to add/edit suppressions (file editing only for now)
"Suggest suppression" button on a finding (later — needs PR integration)
Suppression analytics (how many active per repo over time)
Cross-repo suppression templates
Org-level mandatory suppressions (Pro feature later)

Open questions (decide before Session B)

Where in the response should expiredSuppressionsCount live? Top-level or nested under suppressed? Lean: top-level for easy UI access.
For dependency findings, should the rule ID match by package name or by GHSA ID? Lean: support BOTH — dependency/lodash matches all lodash advisories, dependency/GHSA-xxxx matches one specific advisory.
