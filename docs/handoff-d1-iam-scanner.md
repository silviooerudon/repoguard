# Handoff - RepoGuard, Sessao D1 (IAM Risk Scanner)

## Quem voce esta ajudando

Silvio Gazzoli - solo dev em Dublin, ~10 anos IAM/IGA (SailPoint, CyberArk), construindo RepoGuard como side income. Brasileiro, prefere chat em PT-BR informal sem acentos. Confortavel lendo codigo, menos confortavel escrevendo. Quer comandos prontos pra copy-paste numerados em blocos GRANDES, nao opcoes abertas. Decisoes tecnicas voce toma sem perguntar. So pergunta quando depende de input dele (escopo de produto, expertise IAM/IGA, prioridade). Concorda com tuas recomendacoes por padrao.

Ja avisou pro Claude Code nao pedir aprovacao pra criar/editar arquivos. Trabalha em batches grandes. Emite todo o codigo de uma vez, ele aplica migration manual no meio se precisar, build local, push. NAO trabalhar incremental passo-a-passo.

## Estado do produto (3 maio 2026)

RepoGuard e micro-SaaS de security scan pra repos GitHub. Live em https://repoguard-chi.vercel.app. Em fase pre-distribuicao (1 usuario ativo: o Silvio).

Detectores em prod (8 com Posture):
1. Secrets - 60+ regex patterns
2. Sensitive files - 18 categorias
3. Entropy detection em config files
4. Git history scan (30 commits)
5. SAST regex (11 CWEs)
6. Deps (npm + PyPI)
7. IaC (Dockerfile + GH Actions + npm scripts)
8. Posture Score (Bloco 2 Item 1, fechado em maio 2026) - 8 signals em 3 categorias (branch/docs/deps), gauge + grade A-F + breakdown + quick wins

Stack: Next.js 16.2.3 (App Router) + React 19.2.4 + TypeScript + Tailwind, NextAuth v5 beta GitHub OAuth (scope public_repo), Supabase Postgres+JSONB com SUPABASE_SECRET_KEY (legacy SERVICE_ROLE_KEY desabilitado), Vercel. Codebase em D:/Projetos/repoguard. Branch principal: main. PowerShell, multi-machine. Sempre git pull --rebase antes.

## Roadmap atualizado

Bloco 1 (defensive) - parcial:
- Item 1 Risk Score backend - FEITO
- Item 2 Risk Score UI - FEITO
- Item 3 Suppressions - FEITO
- Item 4 License scan OSS - ADIADO

Bloco 2 (offensive differentiation) - em andamento:
- Item 1 Posture Score - FEITO (sessoes C1-C5, ultimo commit db5a897)
- Item 2 IAM Risk Scanner - PROXIMO (esse handoff)
- Item 3 Supply Chain (typosquatting + postinstall) - depois do IAM
- Item 4 Posture expansion (CODEOWNERS, signed commits, MFA) - filler entre features

## Por que IAM Scanner agora

E a unfair advantage do Silvio. 10 anos de IAM/IGA = expertise rara em SaaS de security. Mercado faz mal: scanners atuais detectam CVE e secret, poucos entendem permissoes amplas, blast radius, role escalation. RepoGuard com IAM scan diferenciado sai de yet another scanner pra scanner com angulo proprio.

Posture ja deu base pra UI de score/grade/breakdown - estrutura visual existe pra reusar.

## Escopo da Sessao D1 (recon + briefing)

D1 e SOMENTE recon + briefing. Nao escrever codigo de detector ainda. Padrao das sessoes anteriores funcionou bem: documento markdown commitavel define escopo antes de qualquer implementacao.

O que D1 precisa produzir:

1. Recon do que ja existe que pode ser reusado. Olhar lib/iac.ts primeiro (ja toca em GH Actions permissions, deve ser base).
2. Decisao de escopo MVP do IAM Scanner. Essa decisao depende do Silvio, voce NAO toma sozinho. Perguntar explicitamente:
   - Quais provedores cobrir no MVP? (AWS IAM JSON / GCP service accounts / Azure Managed Identity / GitHub tokens / Kubernetes RBAC)
   - Quais padroes de risco detectar primeiro? (Resource:* + Action:*, AssumeRole sem condition, wildcards perigosos, etc.)
   - Detectar onde? (apenas em arquivos JSON/YAML de IaC ja escaneados, ou tambem em codigo fonte que monta policy?)
3. Escrever docs/plan-iam-d1-scope.md com escopo amarrado.
4. Commit do briefing antes de qualquer codigo.

O que D1 NAO faz:
- Codigo do detector (vai pra D2 ou alem)
- Mudanca em UI
- Mudanca em backend de rota

## Licoes NAO-NEGOCIAVEIS

1. npm run build local antes de TODO push. Sem excecao. C3 quase quebrou prod por skip dessa regra.
2. Env var em prod sem codigo novo quebra build. Sincronizar var name + codigo no mesmo deploy.
3. NUNCA pedir credenciais no chat. Default e nao precisar. C1 da Posture teve incidente de 3h por causa disso.
4. PowerShell heredoc + acentos = mojibake. Use sempre script Python via arquivo temporario, ASCII puro no conteudo.
5. PowerShell heredoc + caracteres especiais (backticks, dollar, JSX template strings) e armadilha. Padrao validado: arquivo tmp Python com placeholders BTOPEN/BTCLOSE substituidos por chr(96) dentro do Python.
6. Get-Content -Raw em PowerShell le como cp1252 e corrompe UTF-8. Use Python com encoding=utf-8 explicito.
7. Source files do repo ja tem mojibake em emojis (em app/components/*.tsx, page.tsx do scan, page.tsx do scan-public, view/[id]/page.tsx). NAO introduzir mais. ASCII puro nos arquivos novos.
8. No PowerShell, paths com colchetes (app/dashboard/scan/[owner]/[repo]/page.tsx) precisam -LiteralPath, nao -Path.
9. Hard refresh (Ctrl+Shift+R) em smoke test pos-deploy. Cache de bundle JS Vercel pode confundir validacao - C5 perdeu tempo por isso.
10. Schema migration ANTES do push do codigo. Codigo novo grava em colunas, sem elas insert quebra.
11. STOP HERE if build red marcado em negrito antes do bloco git em batches grandes. C3 pushou codigo TS broken por skip disso.

## Padrao de batch grande (validado em C2-C5)

Um batch grande inclui:
- Todo o codigo (criar arquivos, editar arquivos via Python str_replace com asserts em anchors)
- Build local (npm run build)
- STOP HERE if build red marcado em negrito
- Migration manual no meio se houver (Silvio aplica via Supabase SQL editor)
- git status (Silvio confere staged files antes de commit)
- Commit + push
- Smoke test pos-deploy

Adapta ao tamanho real, nao force tudo num bloco se for inutil.

## Recon tecnico vivo (use pra arrancar D1)

Arquivos provavelmente relevantes pro IAM Scanner:
- lib/iac.ts - ja escaneia Dockerfile + GitHub Actions + npm scripts. Olhar primeiro - pode ja detectar GITHUB_TOKEN com permissao excessiva.
- lib/scan.ts - exports GitHubRateLimitError, parseGitHubRateLimit, scanRepo, fetchSuppressionsFile
- lib/risk.ts - flattenScan, scoreRepo, scoring scheme
- lib/posture.ts - assessPosture(owner, repo, accessToken: string | null) - mesmo padrao de assinatura provavel pro IAM scanner
- app/api/scan/[owner]/[repo]/route.ts - linha 54-58 e o Promise.all atual com 4 detectores. IAM scanner adiciona ai como 5o detector.
- app/api/scan-public/[owner]/[repo]/route.ts - mesmo Promise.all simetrico

Migrations vivem em docs/migrations/. Existentes: 001 (risk_score), 002 (suppressed_count), 003 (posture). Proxima provavelmente 004 (iam_*).

Tipo ScanResultFull declarado em DUAS pages:
- app/dashboard/scan/[owner]/[repo]/page.tsx (linha 26-35 aprox)
- app/scan-public/[owner]/[repo]/page.tsx (linha 24-31 aprox)

Tipo SavedScan declarado em app/dashboard/scan/view/[id]/page.tsx - historico ainda nao mostra Risk nem Posture, IAM tambem vai ficar de fora desse caminho. Anotar como tarefa futura unificada.

## Decisoes ja tomadas em sessoes anteriores (nao revisitar)

- assessPosture(owner, repo, accessToken: string | null): Promise<PostureResult>
- 4 colunas posture_* na scans table (score INTEGER, grade TEXT, breakdown JSONB, quick_wins JSONB)
- Backend retorna campo posture no JSON response das duas rotas
- PostureCard renderiza em ambas as rotas (logada e publica) abaixo do RiskCard, antes do meta
- ScanResultFull extendido com posture?: PostureResult em ambas as paginas
- Tipos publicos exportados de lib/posture.ts: PostureGrade, PostureCategoryId, PostureSignal, PostureCategoryBreakdown, QuickWin, PostureResult

Padrao a copiar pro IAM Scanner: mesma estrutura de assinatura, mesmo padrao de Promise.all wiring, mesma estrutura UI (gauge + breakdown + insights), mesma estrutura de persistencia (score + grade/level + breakdown JSONB + insights JSONB).

## Backlog vivo (anotar se cruzar, nao bloquear)

Posture pos-MVP (deferidos C1-C5):
- Fallback main->master quando default branch tem outro nome
- Cache por sha do default branch
- Heuristica security mention mais inteligente
- Monorepo (lockfiles em subpastas)
- Branch protection details como sub-pontos
- CODEOWNERS, signed commits, secret scanning enabled (= Bloco 2 Item 4)
- Smoke test deveria aceitar repo via argv

Bugs conhecidos:
- Migrations SQL files (001/002/003_*.sql) flagadas como Database dump - refinar pattern sensitive-files
- octocat/Hello-World retorna filesScanned=0
- CORS warning github.com/login/oauth no console em scan publico anonimo
- Mojibake em emojis em app/components/*.tsx, page.tsx scan, page.tsx scan-public, view/[id]/page.tsx
- score 0 sintetico em SuppressedFindingItem (cast as PrioritizedFinding)
- Counter no header X findings . Y suppressed deferido
- Postcss card duplica Vulnerable versions
- Race fetch .repoguardignore vs tree scan
- Test coverage gap em suppressions specificity

Tarefas futuras separadas:
- /dashboard/scan/view/[id] nao mostra Risk nem Posture nem IAM - escopo de consolidacao do historico
- License scan OSS (Bloco 1 Item 4 adiado)

## Comandos pra arrancar a D1

cd D:/Projetos/repoguard
git pull --rebase
git status
git log origin/main --oneline -5

Se working tree limpo e ultimo commit for db5a897 feat(posture): show PostureCard on anonymous scan page (C5), arrancar.

Primeiro passo da D1:
1. Inspecionar lib/iac.ts (ja deve ter algo proximo de IAM check em GH Actions)
2. Perguntar Silvio pra escopo MVP (ver lista de perguntas em Escopo da Sessao D1 acima)
3. Escrever docs/plan-iam-d1-scope.md
4. Silvio commita briefing antes de implementacao em D2

## Como Silvio quer trabalhar

- Bloco grande sempre que possivel
- Decisoes tecnicas: voce toma. Decisoes de produto/expertise IAM: pergunta.
- Comandos copy-paste numerados, sem opcoes abertas
- Build local verde antes de push, sem excecao
- Smoke test pos-deploy com hard refresh
- Backlog vivo: anotar, nao bloquear

## Referencias de commits Bloco 2 Item 1 (Posture)

- 3e74ef4 docs: briefing Sessao C1
- 335768e feat(posture): backend lib (C1)
- 15024e8 docs: briefing Sessao C2
- 4bbd31b feat(posture): wire + persistence (C2)
- 002a01d feat(posture): UI card (C3 - tinha bug TS)
- 82ea91a fix(posture): correct field names (C3 fix)
- db5a897 feat(posture): PostureCard on anonymous scan (C5)

(C4 foi sessao de smoke, sem commit de codigo)
