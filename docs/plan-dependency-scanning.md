# Plano: Scan de Dependências Vulneráveis (Opção 2)

**Status**: Planejado | **Sessões estimadas**: 2 | **Decisão em**: 2026-04-12

## Escopo MVP

- **Ecossistema**: Node.js apenas (`package.json`)
- **Modo**: scan unificado — um único botão roda secrets + deps
- **Fonte de CVEs**: npm audit API (`registry.npmjs.org/-/npm/v1/security/advisories/bulk`)

Fora de escopo desta feature: Python, Ruby, Go, Java, `package-lock.json`, sub-dependências transitivas.

## Arquitetura

### Novo arquivo: `lib/deps.ts`

Função principal:

```ts
scanDependencies(owner, repo, accessToken) → DependencyFinding[]
```

Fluxo:
1. Usa GitHub API (já temos em `lib/github.ts`) pra buscar `package.json` na raiz do repo
2. Se não existir, retorna `[]` (sem erro — repo pode não ser Node)
3. Parseia `dependencies` + `devDependencies` do `package.json`
4. Monta payload pra npm audit API:
```json
   { "lodash": ["4.17.15"], "express": ["4.18.2"] }
```
5. POST pra `https://registry.npmjs.org/-/npm/v1/security/advisories/bulk`
6. Parseia resposta, mapeia pra tipo `DependencyFinding`

### Tipo novo

```ts
type DependencyFinding = {
  package: string;
  version: string;
  severity: "critical" | "high" | "moderate" | "low";
  title: string;
  cve: string | null;
  patched_versions: string;
  url: string; // link pra advisory
}
```

### Integração no endpoint existente

Modificar `app/api/scan/[owner]/[repo]/route.ts`:
- Chamar `scanRepo()` (secrets) E `scanDependencies()` em paralelo com `Promise.all`
- Retornar `{ secrets: [...], dependencies: [...] }`

### Página de resultado

Modificar `app/dashboard/scan/[owner]/[repo]/page.tsx`:
- Adicionar segunda seção "Vulnerable Dependencies" abaixo dos secrets
- Mesma UI de cards por severidade
- Se `dependencies.length === 0` e tem `package.json`: mostrar "No known vulnerabilities"
- Se não tem `package.json`: mostrar "No Node.js dependencies detected"

## Plano de execução (2 sessões)

### Sessão 1 (~90 min): Backend
1. Criar `lib/deps.ts` com `scanDependencies()`
2. Testar isolado via script (pegar um repo Node público conhecido com deps velhas)
3. Integrar no endpoint `/api/scan/...` com `Promise.all`
4. Validar retorno via Postman/curl ou DevTools

### Sessão 2 (~60 min): Frontend
5. Adicionar seção de dependências na página de scan result
6. Estados: loading, empty, no-node-project, with-findings
7. Deploy e teste em produção
8. Commit + merge + push

## Riscos conhecidos

- **npm audit API não é documentada oficialmente** — endpoint estável por enquanto, mas pode mudar. Se quebrar, migrar pra OSV.dev (Opção B do planejamento).
- **Repos grandes podem ter `package.json` gigante** — pouco provável quebrar, mas cap em 500 deps pra segurança.
- **False positives possíveis** — advisories podem marcar versões como vulneráveis sem fix disponível. Aceitável no MVP.

## Fora de escopo (próximas features)

- Parse de `package-lock.json` pra pegar versões exatas (hoje pega só o range do `package.json`)
- Sub-dependências transitivas
- Outros ecossistemas (Python, Ruby)
- "Auto-fix" sugerindo versão segura