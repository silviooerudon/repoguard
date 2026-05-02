# Plano - Sessao C1: Posture Score (Backend Lib)

> Bloco 2 / Item 1 da roadmap. Primeira sessao de 4 (C1-C4).
> Escopo: criar `lib/posture.ts` standalone testavel. SEM wiring em rota, SEM migration, SEM UI.

## Objetivo

Ao fim da C1, existe `lib/posture.ts` exportando `assessPosture(owner, repo, accessToken)` que:

1. Faz fetch das fontes GitHub necessarias em paralelo.
2. Computa score 0-100 + letra A/B/C/D/F.
3. Retorna breakdown por categoria + lista de signals + top 5 quick wins.
4. Propaga `GitHubRateLimitError` (rota decide o fallback na C2).
5. Trata 404 e erros de arquivo individual sem quebrar a funcao toda.

E um smoke test em `scripts/smoke-posture.ts` roda local contra 2 repos reais e printa o JSON.

## Tipos publicos (em `lib/posture.ts`)

```ts
export type PostureGrade = "A" | "B" | "C" | "D" | "F"

export type PostureCategoryId = "branch" | "docs" | "deps"

export type PostureSignal = {
  id: string                    // "branch-protection", "security-md", etc
  category: PostureCategoryId
  label: string                 // "SECURITY.md present"
  pointsEarned: number
  pointsMax: number
  satisfied: boolean
}

export type PostureCategoryBreakdown = {
  id: PostureCategoryId
  label: string                 // "Branch protection", "Documentation", "Dependency hygiene"
  pointsEarned: number
  pointsMax: number
  signals: PostureSignal[]
}

export type QuickWin = {
  signalId: string
  label: string                 // "Add SECURITY.md (+15 points)"
  pointsAvailable: number
}

export type PostureResult = {
  score: number                 // 0-100
  grade: PostureGrade
  breakdown: PostureCategoryBreakdown[]
  quickWins: QuickWin[]         // max 5, ordered by pointsAvailable desc
  degraded: boolean             // true se algum fetch nao-404 falhou
}
```

## Signature

```ts
export async function assessPosture(
  owner: string,
  repo: string,
  accessToken: string | null,
): Promise<PostureResult>
```

`accessToken` `null` = scan publico/anonimo. GitHub permite chamadas sem auth (rate limit menor). Mesma assinatura que `scanDependencies`.

## Sinais (decisoes finais)

### Branch protection (35 pts max)

| Signal id | Pontos | Logica |
|---|---|---|
| `branch-protection` | 35 | `GET /repos/{owner}/{repo}/branches/main` retorna `protected: true` |

Se `main` nao existe (404), 0 pontos. Sem fallback pra `master` na v1 (deferido).

### Documentation (35 pts max)

| Signal id | Pontos | Logica |
|---|---|---|
| `security-md` | 15 | `SECURITY.md` existe na raiz |
| `license` | 10 | `LICENSE` OU `LICENSE.md` OU `LICENSE.txt` existe na raiz |
| `readme-substantial` | 5 | `README.md` existe E tem >= 500 chars |
| `readme-mentions-security` | 5 | README contem `/security/i` OU link pra SECURITY.md |

`readme-mentions-security` so conta se `readme-substantial` for satisfeito (sem README, nao da pra mencionar). Mas pontos sao independentes: README curto que menciona security ganha os 5 do mention mas perde os 5 do substantial. Decisao: simplifica e independente. Cada signal e seu proprio gate.

### Dependency hygiene (30 pts max)

| Signal id | Pontos | Logica |
|---|---|---|
| `auto-updates` | 15 | `.github/dependabot.yml` OU `renovate.json` na raiz |
| `lockfile` | 10 | qualquer um: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock` |
| `gitignore-basics` | 5 | `.gitignore` existe E contem `node_modules` E contem `.env` (all-or-nothing) |

## Letra a partir do score

```ts
function gradeFromScore(score: number): PostureGrade {
  if (score >= 90) return "A"
  if (score >= 75) return "B"
  if (score >= 60) return "C"
  if (score >= 40) return "D"
  return "F"
}
```

## Quick Wins

- Iterar todos os signals com `satisfied: false`.
- Ordenar por `pointsMax` desc.
- Pegar top 5.
- Mapa fixo `signalId -> copy`:

```ts
const QUICK_WIN_COPY: Record<string, string> = {
  "branch-protection": "Enable branch protection on main",
  "security-md": "Add SECURITY.md",
  "license": "Add a LICENSE file",
  "readme-substantial": "Expand README (at least 500 chars)",
  "readme-mentions-security": "Mention security/SECURITY.md in README",
  "auto-updates": "Enable Dependabot or Renovate",
  "lockfile": "Commit a lockfile (package-lock.json, yarn.lock, etc.)",
  "gitignore-basics": "Add node_modules and .env to .gitignore",
}
```

Label final: `${copy} (+${pointsAvailable} points)`.

## Estrategia de fetch

Total: 11 chamadas GitHub em paralelo via `Promise.all`.

1. `GET /repos/{owner}/{repo}/branches/main` (1 call)
2. `GET /repos/{owner}/{repo}/contents/{path}` para 10 paths:
   - `SECURITY.md`
   - `LICENSE`
   - `LICENSE.md`
   - `LICENSE.txt`
   - `README.md`
   - `.github/dependabot.yml`
   - `renovate.json`
   - `package-lock.json` (so existencia, nao precisa do conteudo)
   - `yarn.lock` (so existencia)
   - `pnpm-lock.yaml` (so existencia)
   - `poetry.lock` (so existencia)
   - `.gitignore` (precisa do conteudo)

Helpers locais (espelhando `lib/deps.ts`):

```ts
function buildGithubHeaders(token: string | null): HeadersInit
async function fetchRepoFile(owner, repo, path, token): Promise<string | null>  // 404 -> null, content como string
async function fileExists(owner, repo, path, token): Promise<boolean>           // mais barato, usa HEAD se possivel; senao GET e descarta corpo
async function fetchBranch(owner, repo, branch, token): Promise<{ protected: boolean } | null>  // 404 -> null
```

Decisao: `fetchRepoFile` ja serve pra "existe?" tambem (chamador checa `!== null`). Nao vou criar `fileExists` separado pra evitar duplicacao. Aceito o custo de baixar conteudo de lockfiles (sao grandes mas request paralela, e GH ja serve com cache).

Excecao: lockfiles podem ser grandes (>1MB). Pra `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock` vou usar a Contents API com `Accept: application/vnd.github.v3.json` (retorna metadata, nao conteudo) e checar so se 200/404. Isso evita baixar 5MB de lockfile so pra saber se existe.

Implementacao:

```ts
async function repoPathExists(owner, repo, path, token): Promise<boolean> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
    { headers: { Accept: "application/vnd.github.v3.json", ...(token ? { Authorization: `Bearer ${token}` } : {}) }, cache: "no-store" }
  )
  if (res.status === 404) return false
  if (res.ok) return true
  const retry = parseGitHubRateLimit(res)
  if (retry !== null) throw new GitHubRateLimitError(retry)
  return false  // outros erros = trata como nao existe + degraded
}
```

Mas pra README, SECURITY.md, .gitignore precisamos do conteudo. Entao:

- `fetchRepoFile` (com `Accept: application/vnd.github.v3.raw`) pra: README.md, .gitignore
- `repoPathExists` pra: SECURITY.md, LICENSE*, dependabot.yml, renovate.json, todos lockfiles

Total ainda 11 calls paralelas, mais leve.

## Tratamento de erros

- `GitHubRateLimitError`: propaga. Rota decide.
- `404`: signal nao satisfeito, sem flag.
- Qualquer outro erro num fetch individual (network, 500, JSON parse): signal nao satisfeito + `degraded: true` no resultado final.
- Erro fatal (todos os fetches falham, branch fetch da exception nao-rate-limit): nao especial, ainda retorna PostureResult com score baixo + `degraded: true`. Rota nao precisa try/catch separado.

## Funcao pura `computeScore`

Separada da fetch pra facilitar teste mental e refactor:

```ts
type RawSignals = {
  branchProtected: boolean
  hasSecurityMd: boolean
  hasLicense: boolean
  readmeContent: string | null
  hasDependabotOrRenovate: boolean
  hasLockfile: boolean
  gitignoreContent: string | null
  degraded: boolean
}

function computeScore(raw: RawSignals): PostureResult
```

`assessPosture` faz fetch -> monta `RawSignals` -> chama `computeScore`.

## Smoke test

`scripts/smoke-posture.ts`:

```ts
import { assessPosture } from "../lib/posture"

async function main() {
  const token = process.env.GITHUB_TOKEN ?? null

  console.log("=== silviogazzoli/repoguard (with token) ===")
  const r1 = await assessPosture("silviogazzoli", "repoguard", token)
  console.log(JSON.stringify(r1, null, 2))

  console.log("\n=== octocat/Hello-World (no token) ===")
  const r2 = await assessPosture("octocat", "Hello-World", null)
  console.log(JSON.stringify(r2, null, 2))
}

main().catch((e) => { console.error(e); process.exit(1) })
```

Run: `npx tsx scripts/smoke-posture.ts` (com `$env:GITHUB_TOKEN="ghp_..."` setado).

Sanity checks no output:
- Repoguard: score >= 60 esperado (tem README, LICENSE provavel, lockfile certo). Branch protection talvez nao.
- Hello-World: score baixo esperado (README minimo, sem nada).
- `degraded: false` em ambos se rodar limpo.

## Definition of Done

1. `lib/posture.ts` criado, exporta tipos + `assessPosture`.
2. `scripts/smoke-posture.ts` criado, roda local sem erro contra os 2 repos.
3. `npm run build` local verde.
4. Output do smoke test colado no chat pra eu sanity-checkar antes do commit.
5. Commit: `feat(posture): backend lib for repo posture score (C1)`.
6. Push, Vercel deploy verde (deve ser, nao toca em rotas).
7. **Nada de migration, nada de rota, nada de UI.** Isso e C2/C3.

## Backlog deferido (anotar, nao implementar)

- Fallback `main` -> `master` se main nao existir.
- Cache de resultado por (owner, repo, sha do default branch).
- Heuristica de "README mention security" mais inteligente (substring de "responsible disclosure", "vulnerability reporting").
- Suporte a monorepo (lockfiles em subpastas).
- Branch protection details (require PR, require status checks, etc) como sub-pontos.
- Outras categorias futuras: CODEOWNERS, signed commits, secret scanning enabled.

## Ordem de execucao na sessao

1. Eu escrevo `lib/posture.ts` em uma resposta so (e copiavel via heredoc).
2. Voce cola no PowerShell, salva, roda `npm run build`. Se quebrar, manda erro.
3. Eu escrevo `scripts/smoke-posture.ts`.
4. Voce roda smoke test, cola output.
5. Eu sanity-check.
6. Voce commita + pusha.