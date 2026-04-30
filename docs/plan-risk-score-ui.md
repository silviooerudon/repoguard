# Plan: Risk Score UI (Bloco 1, Sessao 2)

**Status:** Planned · **Sessions:** 1 · **Decided:** 2026-04-30

## Why this exists

Backend ships riskScore, riskBreakdown, prioritized. The UI ignores all three. Users still see findings sorted by detector with no headline number. This session closes the loop.

## Design decisions (do not re-debate)

- **Score visualization:** circular gauge (Lighthouse-style), 0-100 number inside, color by band.
  - 0-20: green ("clean")
  - 21-50: yellow ("attention")
  - 51-80: orange ("high risk")
  - 81-100: red ("critical")
- **Breakdown visualization:** mini horizontal bar chart, one bar per severity, widths proportional to that bucket's contribution to the raw total (not capped). Shows where the score is coming from.
- **Findings list:** single unified list ordered by `findingScore` descending. Toggle button to switch to "Group by detector" (legacy view).
- **Pages:** both /dashboard/scan/[owner]/[repo] AND /scan-public/[owner]/[repo] migrate together.
- **Backward compat:** if response has no riskScore (old persisted scans), fall back to legacy "by detector" view. No crash.

## What ships in this session

1. New `app/components/risk-gauge.tsx` - circular gauge (pure SVG, no deps). Props: score, size optional.
2. New `app/components/risk-breakdown.tsx` - horizontal bars per severity (critical/high/medium/low/fixture). Reads riskBreakdown verbatim.
3. New `app/components/finding-card.tsx` - single card that renders ANY finding kind (secret/code/iac/sensitive-file/dependency). Replaces per-section markup duplication.
4. Refactor `app/components/scan-findings.tsx`:
   - Keep existing `SecretCard`-style markup as a fallback "by detector" mode.
   - Add new `PrioritizedList` component that renders `prioritized[]` using `FindingCard`.
   - Export both modes from one file.
5. Both scan pages: replace `<SummaryCard>` row with `<RiskGauge>` + `<RiskBreakdown>` side-by-side, add view toggle, render `PrioritizedList` by default.
6. Mojibake cleanup: replace garbled UTF-8 chars in both pages (`â†` -> arrow, `âœ…` -> checkmark, `â€¢` -> bullet, `â€"` -> em-dash).

## Out of scope (deferred)

- Animation/transitions on score change
- Filter UI (severity chips, kind chips) - waits for suppressions feature
- "Why this score?" explainer modal
- History chart of score over time - waits for diffing feature
- Saved-scan history page (`app/dashboard/scan/view/[id]/page.tsx`) - separate session

## Open questions

- For legacy persisted scans without riskScore, do we recompute client-side or just fall back to legacy view? Lean: legacy view, no recompute. Simpler, honest about data age.
- Should the toggle preference persist across navigations (localStorage) or reset every page load? Lean: reset. Less state, less surprise.

## Test repos for smoke testing

- juice-shop/juice-shop (score 100, broad mix - validates gauge red band, breakdown distribution)
- A clean repo (score low - validates green band)
- A repo with only test fixtures (validates fixture bar)
