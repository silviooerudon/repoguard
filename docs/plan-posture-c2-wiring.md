# Plano - Sessao C2: Posture Score wiring + persistencia

## Objetivo

Wirear assessPosture() (lib/posture.ts, ja em main commit 335768e) nas duas rotas de scan e persistir resultado no Supabase. Sem UI nessa sessao - C3 cuida disso.

## Arquivos tocados

1. docs/migrations/003_add_posture.sql (NOVO)
2. app/api/scan/[owner]/[repo]/route.ts (EDIT)
3. app/api/scan-public/[owner]/[repo]/route.ts (EDIT)

Total: 1 novo, 2 edicoes. Sem mudanca em lib/, sem mudanca em UI, sem mudanca em tipos compartilhados.

## Passo 1 - Migration 003

Criar docs/migrations/003_add_posture.sql:

    ALTER TABLE scans
    ADD COLUMN IF NOT EXISTS posture_score INTEGER,
    ADD COLUMN IF NOT EXISTS posture_grade TEXT,
    ADD COLUMN IF NOT EXISTS posture_breakdown JSONB,
    ADD COLUMN IF NOT EXISTS posture_quick_wins JSONB;

Decisoes:
- Sem NOT NULL e sem default. Scans existentes ficam com NULL nessas colunas (compativel com pre-posture). UI em C3 trata NULL como scan antigo, sem posture.
- posture_score INTEGER (0-100, ja int em PostureResult)
- posture_grade TEXT (livre - ja validado em codigo como A/B/C/D/F)
- posture_breakdown JSONB (array de PostureCategoryBreakdown)
- posture_quick_wins JSONB (array de QuickWin)

Aplicar via Supabase SQL editor antes de fazer push do codigo. Ordem importa: codigo novo grava nas colunas, entao colunas precisam existir antes do deploy.

## Passo 2 - Editar route autenticado

app/api/scan/[owner]/[repo]/route.ts

### 2a. Adicionar import (no topo, junto aos outros imports de @/lib/)

    import { assessPosture } from "@/lib/posture"

### 2b. Modificar Promise.all (linhas 54-57 atuais)

ANTES:

    const [secretsResult, npmResult, pythonDeps] = await Promise.all([
      scanRepo(accessToken, owner, repo, explicitBranch),
      scanDependencies(owner, repo, accessToken),
      scanPythonDependencies(owner, repo, accessToken),
    ])

DEPOIS:

    const [secretsResult, npmResult, pythonDeps, postureResult] = await Promise.all([
      scanRepo(accessToken, owner, repo, explicitBranch),
      scanDependencies(owner, repo, accessToken),
      scanPythonDependencies(owner, repo, accessToken),
      assessPosture(owner, repo, accessToken),
    ])

Rate limit: assessPosture joga GitHubRateLimitError pra cima. Promise.all ja propaga. Catch block existente pega. Zero mudanca no error handling.

Erros nao-rate-limit dentro de assessPosture sao tratados internamente (degraded: true). Sem try/catch externo extra.

### 2c. Adicionar 4 campos no insert do Supabase (linhas 89-100 atuais)

ANTES:

    const { error: dbError } = await supabase.from("scans").insert({
      user_id: userId,
      owner,
      repo,
      result: fullResult,
      duration_ms: secretsResult.durationMs,
      files_scanned: secretsResult.filesScanned,
      secrets_count: secretsResult.findings.length,
      deps_count: npmResult.vulns.length + pythonDeps.length,
      risk_score: assessment.score,
      suppressed_count: suppressionResult.suppressed.length,
    })

DEPOIS:

    const { error: dbError } = await supabase.from("scans").insert({
      user_id: userId,
      owner,
      repo,
      result: fullResult,
      duration_ms: secretsResult.durationMs,
      files_scanned: secretsResult.filesScanned,
      secrets_count: secretsResult.findings.length,
      deps_count: npmResult.vulns.length + pythonDeps.length,
      risk_score: assessment.score,
      suppressed_count: suppressionResult.suppressed.length,
      posture_score: postureResult.score,
      posture_grade: postureResult.grade,
      posture_breakdown: postureResult.breakdown,
      posture_quick_wins: postureResult.quickWins,
    })

### 2d. Adicionar posture no JSON response

ANTES:

    return NextResponse.json({
      ...fullResult,
      riskScore: assessment.score,
      riskBreakdown: assessment.breakdown,
      prioritized: assessment.prioritized,
      suppressed: suppressionResult.suppressed,
      expiredSuppressionsCount: suppressionResult.expiredSuppressionsCount,
    })

DEPOIS:

    return NextResponse.json({
      ...fullResult,
      riskScore: assessment.score,
      riskBreakdown: assessment.breakdown,
      prioritized: assessment.prioritized,
      suppressed: suppressionResult.suppressed,
      expiredSuppressionsCount: suppressionResult.expiredSuppressionsCount,
      posture: postureResult,
    })

Decisao: expor o PostureResult inteiro como posture no response (objeto aninhado, nao spreaded). UI em C3 consome data.posture.score, data.posture.grade, etc. Mantem namespace limpo e nao colide com risco.

## Passo 3 - Editar route publico

app/api/scan-public/[owner]/[repo]/route.ts

Mesmo padrao do autenticado, sem o insert do Supabase (rota anonima nao persiste).

### 3a. Import

    import { assessPosture } from "@/lib/posture"

### 3b. Promise.all (linhas 36-40 atuais)

ANTES:

    const [secretsResult, npmResult, pythonDeps] = await Promise.all([
      scanRepo(null, owner, repo, explicitBranch),
      scanDependencies(owner, repo, null),
      scanPythonDependencies(owner, repo, null),
    ])

DEPOIS:

    const [secretsResult, npmResult, pythonDeps, postureResult] = await Promise.all([
      scanRepo(null, owner, repo, explicitBranch),
      scanDependencies(owner, repo, null),
      scanPythonDependencies(owner, repo, null),
      assessPosture(owner, repo, null),
    ])

### 3c. Response JSON

ANTES:

    return NextResponse.json({
      ...fullResult,
      riskScore: assessment.score,
      riskBreakdown: assessment.breakdown,
      prioritized: assessment.prioritized,
      suppressed: suppressionResult.suppressed,
      expiredSuppressionsCount: suppressionResult.expiredSuppressionsCount,
    })

DEPOIS:

    return NextResponse.json({
      ...fullResult,
      riskScore: assessment.score,
      riskBreakdown: assessment.breakdown,
      prioritized: assessment.prioritized,
      suppressed: suppressionResult.suppressed,
      expiredSuppressionsCount: suppressionResult.expiredSuppressionsCount,
      posture: postureResult,
    })

## Passo 4 - Build local

    npm run build

Verde antes de push. Sem excecao.

## Passo 5 - Migration em prod

Antes do push, aplicar 003 em Supabase via SQL editor. Codigo novo grava nessas colunas - sem elas, insert quebra.

Ordem:
1. Aplicar SQL no Supabase
2. Confirmar colunas: SELECT column_name FROM information_schema.columns WHERE table_name = scans AND column_name LIKE posture_%; (deve retornar 4 linhas)
3. Push

## Passo 6 - Push e deploy

    git add docs/migrations/003_add_posture.sql app/api/scan/[owner]/[repo]/route.ts app/api/scan-public/[owner]/[repo]/route.ts
    git commit -m "feat(posture): wire assessPosture into scan routes + persistence (C2)"
    git push

Aguardar Vercel deploy verde.

## Passo 7 - Smoke test pos-deploy

1. Em prod, logar e rodar scan em silviooerudon/repoguard
2. Conferir response no DevTools Network: deve ter campo posture com score/grade/breakdown/quickWins
3. Em /dashboard/history, conferir que scan novo aparece (UI nao mostra posture ainda - isso e C3)
4. No Supabase: SELECT id, owner, repo, posture_score, posture_grade FROM scans ORDER BY created_at DESC LIMIT 1; - confirmar que as colunas estao preenchidas

DoD da C2 atingida quando todos os 4 itens do smoke acima passam.

## Riscos e mitigacoes

- Risco: assessPosture lento em repo grande adiciona latencia. Mitigacao: 13 fetches paralelos via Promise.all interno, ja validado em C1. Nao-bloqueante pro Promise.all externo.
- Risco: Coluna JSONB grande estoura limite de row do Postgres. Mitigacao: breakdown e quickWins sao listas curtas (3 categorias, max 5 quick wins). Tamanho irrelevante.
- Risco: Migration aplicada antes do push, push falha, prod fica com schema novo + codigo velho. Mitigacao: Codigo velho ignora colunas novas (insert nao referencia, schema-additive). Sem breakage.
- Risco: Push antes de migration aplicada. Mitigacao: Inverte ordem dos passos 5 e 6. Insert vai falhar com column does not exist e cai no console.error do dbError check. Scan ainda retorna response. Mas nao queremos isso - aplicar migration ANTES de push.

## Backlog tecnico vivo

- Posture C1 deferidos seguem deferidos (fallback master, cache por sha, etc.)
- Mojibake em components - nao tocar
- Teste de integracao da rota com posture - C4 ou depois
