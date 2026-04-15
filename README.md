# RepoGuard

> Lightweight GitHub security scanner for solo devs and small teams. Live at **[repoguard-chi.vercel.app](https://repoguard-chi.vercel.app)**.

Scans your GitHub repos for exposed secrets and vulnerable dependencies. No CLI, no config files, no complicated setup — sign in with GitHub, click Scan, get results in under a minute.

## Why I built this

I've spent 10+ years in Identity & Access Management — the field that exists because credentials leak and people get owned. Tools like Snyk and GitGuardian are great, but priced for teams with security budgets. Solo devs and tiny startups skip security scanning entirely because the bar to entry is too high.

RepoGuard is my attempt at the smallest useful security tool: scan a repo in one click, see what's wrong, fix it. Built in public.

## Features

- 🔑 **Secret scanning** — detects 16 types of exposed credentials (AWS keys, GitHub tokens, Stripe keys, OpenAI keys, private keys, JWTs, DB connection strings, and more)
- 📦 **Dependency scanning** — checks `package.json` against the npm advisory database for known vulnerabilities (CVSS scores + GHSA links)
- 📜 **Scan history** — every scan is saved so you can revisit findings without re-scanning
- ⚡ **Fast** — secret + dependency scans run in parallel, typically under 30 seconds
- 🔒 **Privacy-first** — we store metadata and findings, never your source code or full secrets

## What we detect

**Secrets (16 patterns):** AWS access keys, GitHub PATs, Stripe live/test keys, OpenAI API keys, Google API keys, Slack tokens, SendGrid keys, Twilio keys, RSA/EC private keys, JWTs, generic high-entropy strings, database connection strings with embedded passwords, and more.

**Dependencies:** Node.js packages via the npm audit bulk API, with severity (low → critical), affected version ranges, and direct links to GitHub Security Advisories.

## Privacy

We **never** store:
- Your source code
- Your GitHub access token (only used at scan time, never persisted)
- Full secret values (only the type, file path, and line number)

We **do** store: scan metadata (owner/repo, timestamp, counts) and findings (file paths + line numbers + secret type) so you can review history.

Data lives in Supabase (EU region) and Vercel. You can revoke access anytime via your [GitHub settings](https://github.com/settings/applications). Full details on the [security page](https://repoguard-chi.vercel.app/security).

## Tech stack

- **Framework:** Next.js 16 (App Router) + TypeScript + Tailwind
- **Auth:** NextAuth v5 (GitHub OAuth)
- **Database:** Supabase (Postgres + JSONB)
- **Hosting:** Vercel
- **APIs:** GitHub REST API v3, npm audit bulk endpoint

## Run locally

Prereqs: Node 20+, a GitHub account, a Supabase project (free tier is fine).

```bash
git clone https://github.com/silviooerudon/repoguard.git
cd repoguard
npm install
```

Create `.env.local`:

```bash
AUTH_SECRET=             # generate with: npx auth secret
AUTH_GITHUB_ID=          # from a GitHub OAuth App pointing to localhost:3000
AUTH_GITHUB_SECRET=
SUPABASE_URL=
SUPABASE_SERVICE_ROLE_KEY=
```

Create the `scans` table in Supabase (schema in `docs/`), then:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Roadmap

Built in public. Rough order of what's next, depending on user feedback:

- [ ] Reduce default OAuth scope to `public_repo` (private repo access becomes opt-in)
- [ ] No-login scan mode for public repos (paste URL → scan)
- [ ] Python dependency scanning (via OSV.dev)
- [ ] Switch from OAuth App to GitHub App (per-repo permissions)
- [ ] Webhook-based continuous scanning

If something here matters to you, [open an issue](https://github.com/silviooerudon/repoguard/issues) — feedback shapes priorities.

## Author

Built by **Silvio Gazzoli** — IAM/IGA specialist based in Dublin, Ireland. 10+ years working with SailPoint, CyberArk, and enterprise identity governance.

[LinkedIn](https://www.linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a/) · [GitHub](https://github.com/silviooerudon)

## License

MIT