# Bloco 1 · Item 3 · Sessão B — Suppressions UI

> **Pré-requisitos confirmados:** 5 commits da Sessão A em `origin/main`, migration `002_add_suppressed_count.sql` aplicada em prod, smoke test ok (suppressed=[], expiredSuppressionsCount=0 persistido).

## Objetivo

Expor o resultado das suppressions (já calculado no backend) na página `/dashboard/scan/[owner]/[repo]`. O usuário precisa ver:

- Quais findings foram suprimidos e por qual regra do `.repoguardignore`
- Quando uma suppression expirou (precisa revisar)
- Glance no header de quanto está sendo escondido

Nada de re-implementar lógica de matching — backend já entrega tudo pronto via `suppressed`, `expiredSuppressionsCount` e `prioritized`.

## Shape do payload (recap)

```ts
{
  ...fullResult,
  riskScore,
  riskBreakdown,
  prioritized: Finding[],          // já filtrado, é o que a UI principal renderiza
  suppressed: SuppressedFinding[], // o foco desta sessão
  expiredSuppressionsCount: number
}

type SuppressedFinding = {
  finding: Finding
  suppression: {
    pathGlob: string
    ruleGlob?: string
    reason?: string
    expires?: string  // ISO date
    sourceLine: number
  }
  expired: boolean
}
```

## Decisões técnicas (já tomadas)

1. **Componente novo `SuppressedFindingsSection`** — não polui o card de findings existente; a shape com `suppression` + `expired` é distinta o bastante.
2. **`ExpiredSuppressionsBanner` como componente separado** — renderiza no topo da página, acima do risk score. Cor warning (yellow), não danger — é "revise" não "você está exposto".
3. **Collapse via `<details>`/`<summary>` nativo** — zero JS state, acessível, fácil de trocar por animação depois se quiser.
4. **Empty state:** quando `suppressed.length === 0`, a seção não renderiza. Sem placeholder. Se o user nunca usou suppressions, a UI fica idêntica ao que era antes.
5. **Counter no header:** `"X findings · Y suppressed"` ao lado do título do scan, com `Y suppressed` em muted color quando 0 e clicável quando > 0 (scrolla pra seção).

## Arquivos previstos

**Novos:**
- `components/scan/SuppressedFindingsSection.tsx`
- `components/scan/ExpiredSuppressionsBanner.tsx`
- `components/scan/SuppressedFindingItem.tsx` (item individual dentro da seção)

**Editados:**
- `app/dashboard/scan/[owner]/[repo]/page.tsx` (ou onde o scan render mora — Bloco 1 confirma o path exato)
- Possivelmente o componente que renderiza o header/título do scan, pra adicionar o counter

---

## Bloco 1 — Reconhecimento e tipos compartilhados

**Objetivo:** Mapear onde o scan é renderizado hoje e centralizar o tipo `SuppressedFinding` num arquivo importável pelos novos componentes.

### Step 1.1 — Localizar arquivos relevantes

Comandos PowerShell pra mapear:

```powershell
git pull --rebase
Get-ChildItem -Path app/dashboard/scan -Recurse -Filter "*.tsx"
Get-ChildItem -Path components/scan -Recurse -ErrorAction SilentlyContinue
Select-String -Path "app/**/*.tsx","components/**/*.tsx" -Pattern "prioritized|riskScore" -List
```

**Reportar de volta:** lista de arquivos retornados, em particular:
- O path exato do `page.tsx` do scan
- Se `components/scan/` já existe ou precisa ser criado
- Quais componentes hoje consomem `prioritized` e `riskScore`

### Step 1.2 — Exportar tipos de `lib/suppressions.ts`

Confirmar que `Suppression`, `SuppressedFinding`, `SuppressionResult` já estão `export`ados (devem estar, da Sessão A). Se não, adicionar export.

```powershell
Select-String -Path "lib/suppressions.ts" -Pattern "^export "
```

**Reportar:** lista de exports.

### Step 1.3 — Inspecionar como o scan page recebe dados

Abrir o `page.tsx` do scan e identificar:
- É server component fetchando direto, ou client component recebendo props?
- O response do `/api/scan/...` está sendo tipado? Onde?
- Existe um tipo central tipo `ScanResult` ou cada componente reinventa?

**Reportar:** trecho do componente onde o response é consumido (até ~30 linhas). Daqui sai a decisão de onde plugar `suppressed` e `expiredSuppressionsCount`.

**Commit ao fim do Bloco 1:** nenhum. É só recon.

---

## Bloco 2 — Componentes novos

**Objetivo:** Criar os 3 componentes (banner, section, item) standalone, sem ainda integrar na page. Render-testáveis isoladamente.

### Step 2.1 — `ExpiredSuppressionsBanner.tsx`

```tsx
// components/scan/ExpiredSuppressionsBanner.tsx
type Props = { count: number }

export function ExpiredSuppressionsBanner({ count }: Props) {
  if (count === 0) return null
  return (
    <div role="alert" className="...yellow/warning styling...">
      <strong>{count} expired {count === 1 ? 'suppression' : 'suppressions'}</strong>
      {' '}in your .repoguardignore. Review and update or remove them.
    </div>
  )
}
```

Styling: seguir o que o resto do dashboard usa (Tailwind, cores warning/yellow). Ícone opcional — se já houver lib de ícones no projeto, usar; senão, sem ícone.

### Step 2.2 — `SuppressedFindingItem.tsx`

Renderiza um item individual. Layout proposto:

```
┌─────────────────────────────────────────────────────┐
│ [secret] src/legacy/old-config.ts            [expired] │
│   Rule: aws-access-key-id                              │
│   Suppressed by: src/legacy/**  →  reason: "migration" │
│   Expires: 2024-12-31 (line 4 of .repoguardignore)     │
└─────────────────────────────────────────────────────┘
```

Props:
```ts
type Props = { item: SuppressedFinding }
```

Renderiza:
- `item.finding.kind` como badge (cor por kind, mesma paleta do prioritized)
- `item.finding.path` 
- Primary rule ID (depende do kind — provavelmente `item.finding.rule` ou `item.finding.ruleId`; checar shape real do `Finding` no Bloco 1)
- `item.suppression.pathGlob` + opcionalmente `ruleGlob`
- `item.suppression.reason` se presente
- `item.suppression.expires` formatado (e badge `expired` em vermelho se `item.expired === true`)
- `Line N of .repoguardignore` em muted

**Reportar diff antes de aplicar.**

### Step 2.3 — `SuppressedFindingsSection.tsx`

Wrapper colapsável.

```tsx
type Props = { items: SuppressedFinding[] }

export function SuppressedFindingsSection({ items }: Props) {
  if (items.length === 0) return null
  return (
    <details className="..." id="suppressed-section">
      <summary className="cursor-pointer ...">
        Suppressed ({items.length})
      </summary>
      <div className="mt-4 space-y-2">
        {items.map((item, i) => (
          <SuppressedFindingItem key={`${item.finding.path}-${i}`} item={item} />
        ))}
      </div>
    </details>
  )
}
```

`<details>` fechado por default (sem `open` prop). `id` na seção pra permitir scroll-to via anchor.

**Reportar diff antes de aplicar.**

**Commit ao fim do Bloco 2:**
```
feat(suppressions): add UI components for suppressed findings

- ExpiredSuppressionsBanner: warning banner when ignore rules expire
- SuppressedFindingsSection: collapsible <details> wrapper
- SuppressedFindingItem: individual suppressed finding with rule context
```

---

## Bloco 3 — Integração na página de scan + counter no header

**Objetivo:** Plugar tudo no fluxo real. Após este bloco a feature está visível em produção.

### Step 3.1 — Estender o tipo do scan response (se aplicável)

Se o Bloco 1 revelar um tipo `ScanResult` central, estendê-lo:

```ts
type ScanResult = {
  // ...existing
  suppressed: SuppressedFinding[]
  expiredSuppressionsCount: number
}
```

Importar `SuppressedFinding` de `lib/suppressions.ts`.

### Step 3.2 — Renderizar banner + section na page

No `page.tsx` (ou no client component que recebe os dados):

```tsx
// imports novos
import { ExpiredSuppressionsBanner } from '@/components/scan/ExpiredSuppressionsBanner'
import { SuppressedFindingsSection } from '@/components/scan/SuppressedFindingsSection'

// no JSX, ordem proposta:
<ExpiredSuppressionsBanner count={result.expiredSuppressionsCount} />
<RiskScoreCard ... />          // já existe
<PrioritizedFindings ... />    // já existe (nome real depende do Bloco 1)
<SuppressedFindingsSection items={result.suppressed} />
```

**Reportar diff antes de aplicar.**

### Step 3.3 — Counter no header

Adicionar ao componente que renderiza o título do scan:

```tsx
<h1>{owner}/{repo}</h1>
<p className="text-sm text-muted-foreground">
  {prioritized.length} findings
  {suppressed.length > 0 && (
    <>
      {' · '}
      <a href="#suppressed-section" className="hover:underline">
        {suppressed.length} suppressed
      </a>
    </>
  )}
</p>
```

Quando `suppressed.length === 0` o segundo span não renderiza.

**Reportar diff antes de aplicar.**

### Step 3.4 — Sanity check em prod

Pre-merge checklist:
1. `npm run build` local passa
2. `npm run lint` sem erros novos
3. Dev server: scan de repo conhecido sem `.repoguardignore` → seção não aparece, counter mostra só `X findings`
4. Dev server: scan de repo com `.repoguardignore` válido → seção aparece colapsada, counter mostra `X findings · Y suppressed`, link scrolla
5. Dev server: scan com suppression `expires` no passado → banner amarelo aparece no topo

Se faltar repo de teste, criar `.repoguardignore` no próprio repo do RepoGuard com 1 regra real e 1 expirada pra testar.

**Commit ao fim do Bloco 3:**
```
feat(suppressions): wire UI into scan page

- Banner for expired suppressions at top of scan view
- Collapsible suppressed findings section below prioritized
- Header counter shows "X findings · Y suppressed"
```

---

## Backlog técnico — checklist durante a sessão

Anotar (não resolver) se cruzar:
- [ ] pathGlob com `[abc]` mal-parseado
- [ ] Data malformado virando `unknown/unknown` silenciosamente
- [ ] Race fetch `.repoguardignore` vs tree scan
- [ ] Deps em monorepo precisando `**`
- [ ] Test coverage: specificity ordering
- [ ] Postcss card duplicando "Vulnerable versions"

**Bonus se sobrar tempo:** trocar gauge size 160 → 200 do Item 2. Mudança trivial, é localizar `width={160}`/`height={160}` no componente do risk score e bumpar.

---

## Definition of done

- [ ] 3 componentes novos criados em `components/scan/`
- [ ] Page de scan importa e renderiza os 3
- [ ] Header conta `X findings · Y suppressed`
- [ ] Banner de expired aparece quando `expiredSuppressionsCount > 0`
- [ ] Seção colapsada por default, aparece só quando `suppressed.length > 0`
- [ ] Build + lint limpos
- [ ] 2 commits em `main`: components, integration
- [ ] Push pra `origin/main`
- [ ] Smoke em prod: scan de repo com `.repoguardignore` retorna UI esperada
