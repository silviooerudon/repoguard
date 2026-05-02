# Baseline metrics — pre-distribution snapshot

This file is a frozen snapshot of usage metrics taken **before** any public distribution effort. It exists to compare against future numbers and decide when to revisit billing.

**Do not update this file in place.** Add a new dated section below the baseline when you take a new measurement, so the trajectory stays visible.

---

## Snapshot: 2026-05-01

Taken right after the decision to pause billing work and focus on distribution. Source: direct query against the `scans` table in Supabase (EU). Query is reproducible from `docs/analytics-queries.md`.

| Metric                          | Value                          |
| ------------------------------- | ------------------------------ |
| Total scans (all time)          | 21                             |
| Total scans (last 30 days)      | 21                             |
| Total scans (last 7 days)       | 13                             |
| Distinct users (all time)       | 1                              |
| Distinct users (last 30 days)   | 1                              |
| Distinct users (last 7 days)    | 1                              |
| Earliest scan recorded          | 2026-04-14                     |
| Latest scan recorded            | 2026-05-01                     |
| Users (last 30 days)            | `silviooerudon` (Silvio only)  |

**Interpretation:** RepoGuard has been live but not distributed. The only active user is the author. All scan activity is internal dogfooding. Billing is parked until distribution produces real users.

**Revisit trigger:** measure again after the first public distribution push (Show HN, r/devops post, LinkedIn, etc.). Decision points:

- **< 10 distinct users in last 30 days** → continue distribution, do not build billing
- **10–30 distinct users in last 30 days** → build usage gate + counters (PR 1, PR 2 from billing plan), validate price with the most active 3–5 users before Stripe work
- **> 30 distinct users in last 30 days** → green light full billing rollout in plan order (1 → 2 → 4 → 5 → 3)

---

## Snapshot: YYYY-MM-DD

_Add the next snapshot here. Do not delete previous entries._
