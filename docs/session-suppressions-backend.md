# Sessão A — Suppressions Backend

## Contexto

RepoGuard é um SaaS de scan de segurança para repos GitHub. Esta sessão implementa o **backend** do sistema de suppressions (`.repoguardignore`), que permite aos usuários silenciar findings específicos via um arquivo no root do repo.

Decisões já tomadas (não re-debater):
- Arquivo: `.repoguardignore` no repo root, formato linha-a-linha estilo `.gitignore`
- Granularidade: path glob (obrigatório) + rule glob opcional + reason opcional + expires opcional
- Behavior: suppressed findings vão pra array `suppressed` separado, NÃO entram no `riskScore`/`prioritized`
- Glob library: `minimatch`
- Sessão B (UI) virá depois, separada

Plano detalhado: `docs/plan-suppressions.md` (já commitado, leia antes de começar).

## Regras de execução

1. Execute UM step por vez. Pare ao final de cada step e reporte:
   - O que fez (arquivos criados/modificados, comandos executados)
   - Output relevante (erros, warnings, resultado de testes)
   - Aguarde confirmação "go" antes do próximo step
2. Antes de aplicar diff em arquivo existente, mostre o diff e espere aprovação
3. Commits separados por unidade lógica — eu indico quando commitar
4. Se algo divergir do plano, pare e pergunte antes de improvisar

## Pré-requisitos

Antes do Step 1, leia (sem modificar):
- `docs/plan-suppressions.md`
- `lib/scan.ts` (entender shape atual de findings)
- `lib/risk.ts` (entender como `scoreRepo` é chamado)
- `app/api/scan/[owner]/[repo]/route.ts` (entender flow authenticated)
- `app/api/scan-public/[owner]/[repo]/route.ts` (entender flow anonymous)

Reporte um resumo curto do que encontrou (estrutura de findings, onde `scoreRepo` é chamado hoje, shape da response). Pare e aguarde "go".

---

## Step 1 — Install minimatch

Execute:

    npm install minimatch
    npm install --save-dev @types/minimatch

Verifique versão instalada e reporte. Pare e aguarde "go".

---

## Step 2 — Criar lib/suppressions.ts (types only)

Crie `lib/suppressions.ts` com APENAS os types abaixo, sem implementação ainda:

    export type Suppression = {
      pathGlob: string;
      ruleGlob?: string;
      reason?: string;
      expires?: string; // ISO date YYYY-MM-DD
      sourceLine: number; // 1-indexed line in .repoguardignore
    };

    export type SuppressedFinding = {
      finding: unknown; // será tipado quando integrarmos
      suppression: Suppression;
      expired: boolean;
    };

    export type SuppressionResult = {
      kept: unknown[]; // findings que NÃO foram suprimidos
      suppressed: SuppressedFinding[];
      expiredSuppressionsCount: number;
    };

Mostre o arquivo. Pare e aguarde "go".

---

## Step 3 — Implementar parseSuppressions

Adicione em `lib/suppressions.ts` a função `parseSuppressions(content: string): Suppression[]`:

Spec:
- Recebe o conteúdo bruto do `.repoguardignore`
- Divide por `\n`
- Para cada linha (1-indexed):
  - Trim
  - Se vazia ou começa com `#` → skip
  - Senão, parse como: `pathGlob [rule=<ruleGlob>] [reason="<reason>"] [expires=YYYY-MM-DD]`
  - Os modificadores entre colchetes são opcionais e podem aparecer em qualquer ordem
  - `pathGlob` é o primeiro token até o primeiro espaço ou `[`
- Validações:
  - Se `pathGlob` vazio → skip linha
  - Se `expires` não for ISO date válido → ignora o campo (não falha a linha)
- Retorna array de `Suppression`

Sugestão de implementação (regex simples + split):
- Extrair `pathGlob` primeiro (tudo antes do primeiro `[` ou EOL)
- Para cada modificador, regex tipo `\[(\w+)=([^\]]+)\]`

Mostre o diff. Pare e aguarde "go".

---

## Step 4 — Implementar findRuleIdForFinding

Adicione em `lib/suppressions.ts`:

    export function findRuleIdForFinding(finding: any): string

Spec — gera rule-id canônico baseado no shape do finding:
- Secret finding (tem `patternId` ou `category === "secret"`) → `"secret/<patternId>"` ou `"secret/<subcategory-slug>"`
- Code/SAST finding (tem `cweId` ou `category === "code"`) → `"code/<cweId-slug>"` (ex: `code/cwe-918` para SSRF)
- Dependency finding (tem `ghsaId` ou `package`) → `"deps/<package>"` (sem versão)
- Sensitive file finding → `"sensitive-file/<category>"`
- Entropy finding → `"entropy/<filetype>"`
- Git history finding → `"git-history/<patternId>"` (mesmo namespace de secret mas prefixo distinto)
- IaC finding → `"iac/<category>"` (ex: `iac/dockerfile-root`)
- Fallback → `"unknown/unknown"`

Adicione TAMBÉM:

    export function findAlternateRuleIds(finding: any): string[]

Para deps findings, retorna IDs alternativos pra suppression matchar:
- `deps/<package>`
- `deps/<package>/<ghsaId>` se existir
- `deps/<ghsaId>` se existir

Para outros tipos, retorna `[findRuleIdForFinding(finding)]`.

IMPORTANTE: antes de implementar, **leia `lib/scan.ts` e identifique os shapes reais** dos findings de cada detector. Reporte o shape de cada tipo antes de codar — quero validar os mappings.

Pare e aguarde "go".

---

## Step 5 — Implementar applySuppressions

Adicione em `lib/suppressions.ts`:

    export function applySuppressions(
      findings: any[],
      suppressions: Suppression[],
      now: Date = new Date()
    ): SuppressionResult

Spec:
- Para cada finding:
  - Calcula `path` do finding (campo varia por detector — investigue, geralmente `path` ou `filePath`)
  - Gera lista de rule IDs via `findAlternateRuleIds(finding)`
  - Procura primeira suppression que matcha:
    - Path: `minimatch(path, suppression.pathGlob)` — `true` significa match
    - Rule: se `suppression.ruleGlob` definido, **algum** ruleId deve matchar via `minimatch(ruleId, suppression.ruleGlob)`; se não definido, qualquer rule passa
  - Ordem de matching: **mais específica primeiro**. Heurística: ordene `suppressions` antes do loop por:
    - `ruleGlob` definido > não definido (peso 2)
    - `pathGlob` sem wildcards > com wildcards (peso 1)
    - Em empate, ordem original
  - Se matchou:
    - Calcula `expired`: se `suppression.expires` definido e `now > parseISO(expires)` → `expired = true`
    - Push pra `suppressed` array
  - Senão: push pra `kept`
- Conta `expiredSuppressionsCount` (suppressions que matcharam algo E estão expiradas)

Mostre o diff. Pare e aguarde "go".

---

## Step 6 — Fetch de .repoguardignore em lib/scan.ts

Adicione em `lib/scan.ts` uma função pra buscar o `.repoguardignore` do repo via GitHub API:

    async function fetchSuppressionsFile(
      octokit: any,
      owner: string,
      repo: string,
      ref?: string
    ): Promise<string | null>

Spec:
- Best-effort: se 404, retorna `null` sem erro
- Se sucesso, retorna conteúdo decodificado
- Qualquer outro erro → loga e retorna `null` (soft-fail)
- NÃO conta contra o limite de 300 files

NÃO chame ela ainda — apenas adicione. Mostre o diff e onde a colocou (escolha local apropriado, perto de outras funções de fetch).

Pare e aguarde "go".

---

## Step 7 — Wire na rota authenticated

Edite `app/api/scan/[owner]/[repo]/route.ts`:

1. Import `parseSuppressions, applySuppressions` de `lib/suppressions`
2. Import `fetchSuppressionsFile` de `lib/scan`
3. Após findings serem coletados mas **ANTES** de `scoreRepo`:
   - Chame `fetchSuppressionsFile`
   - Se retornou conteúdo, `parseSuppressions` → `applySuppressions(allFindings, suppressions)`
   - `allFindings` passa a ser `result.kept`
   - Guarde `result.suppressed` e `result.expiredSuppressionsCount`
4. `scoreRepo` continua recebendo apenas `kept`
5. Response inclui:
   - `suppressed: result.suppressed` (array)
   - `expiredSuppressionsCount: result.expiredSuppressionsCount` (number)
6. Persistência Supabase: adicione `suppressed_count: result.suppressed.length` no insert (coluna ainda não existe, será criada na migration do Step 9 — pode haver erro temporário de coluna, OK)

MOSTRE O DIFF antes de aplicar. Pare e aguarde "go".

---

## Step 8 — Wire na rota pública

Edite `app/api/scan-public/[owner]/[repo]/route.ts`:

Mesma lógica do Step 7, mas SEM Supabase (sem persistência). Apenas:
- Fetch + parse + apply
- Adicionar `suppressed` e `expiredSuppressionsCount` na response

MOSTRE O DIFF. Pare e aguarde "go".

---

## Step 9 — Migration Supabase

Crie `docs/migrations/002_add_suppressed_count.sql` com:

    ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS suppressed_count INTEGER NOT NULL DEFAULT 0;

NÃO execute. Apenas crie o arquivo. Mostre o conteúdo. Pare e aguarde "go".

---

## Step 10 — Smoke test synthetic

Crie `scripts/test-suppressions.ts`:

Spec:
- Script Node standalone (executável via `npx tsx scripts/test-suppressions.ts`)
- NÃO chama GitHub API. Usa fixtures inline.
- Define ~5 findings sintéticos cobrindo: secret, code/cwe, deps com ghsa, sensitive-file, entropy
- Define um `.repoguardignore` mock multi-linha com:
  - Path glob simples (`tests/**`)
  - Path + rule glob (`legacy/**` + `rule=secret/*`)
  - Suppression expirada (`expires=2024-01-01`)
  - Linha de comentário (`# isto é comentário`)
  - Linha vazia
- Chama `parseSuppressions` → `applySuppressions`
- Imprime resultado formatado:
  - Total parsed suppressions
  - Findings kept (count + lista resumida)
  - Findings suppressed (count + cada um com qual suppression matchou + expired flag)
  - expiredSuppressionsCount

Execute `npx tsx scripts/test-suppressions.ts` e cole o output. Pare e aguarde validação.

---

## Step 11 — Commit

Após eu validar tudo, organize commits separados:

1. `feat(suppressions): add lib/suppressions.ts with parser and matcher`
   - `lib/suppressions.ts`
   - `package.json` + `package-lock.json` (minimatch)
2. `feat(suppressions): wire into scan routes`
   - `lib/scan.ts` (fetchSuppressionsFile)
   - `app/api/scan/[owner]/[repo]/route.ts`
   - `app/api/scan-public/[owner]/[repo]/route.ts`
3. `chore(db): migration for suppressed_count column`
   - `docs/migrations/002_add_suppressed_count.sql`
4. `test(suppressions): synthetic smoke test`
   - `scripts/test-suppressions.ts`

Mostre `git status` antes de cada commit. NÃO faça push — eu faço manualmente.

---

## Out of scope desta sessão

- UI de suppressions (Sessão B)
- Aplicar a migration no Supabase (eu rodo manual)
- Push pro origin
- Auto-detect dos próprios arquivos do RepoGuard como findings (backlog item 1)
