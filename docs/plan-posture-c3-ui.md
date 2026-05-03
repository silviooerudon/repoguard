# Plano - Sessao C3: Posture Score UI

## Objetivo

Adicionar PostureCard na pagina de scan novo (/dashboard/scan/[owner]/[repo]). Mostra gauge + grade letter + breakdown 3-categorias + quick wins. Sem mexer em scans antigos (/scan/view/[id]) - escopo separado anotado no backlog.

## Arquivos tocados

1. app/components/posture-gauge.tsx (NOVO) - SVG gauge com cor invertida (verde alto = bom) + grade letter
2. app/components/posture-card.tsx (NOVO) - container com gauge + breakdown bars + quick wins list
3. app/dashboard/scan/[owner]/[repo]/page.tsx (EDIT) - extender ScanResultFull, importar e renderizar PostureCard abaixo do RiskCard

Total: 2 novos, 1 edit. Zero mudanca em backend, zero mudanca em /api/, zero mudanca em scans antigos.

## Decisoes de design

- PostureGauge: mesma estrutura SVG do RiskGauge (270deg arc, mesma rotation 135), mas mapeamento de cor invertido. 90+ verde, 75-89 azul, 60-74 amarelo, 40-59 laranja, <40 vermelho. Centro do gauge mostra letra grande (A/B/C/D/F) + score pequeno embaixo.
- PostureCard: mesmo container visual do RiskCard (bg-gray-900 border border-gray-800 rounded-xl p-6 flex flex-col md:flex-row gap-6). Esquerda gauge, direita breakdown + quick wins.
- Breakdown bars: 3 mini-bars horizontais (Branch / Docs / Deps), cada uma mostra X/Y points + barra preenchida proporcional. Cor da barra segue mesma escala do gauge.
- Quick wins: ul com max 5 items. Cada item: signal label + (+N pts) em cinza.
- Degraded badge: se posture.degraded, mostra texto Partial data em cinza ao lado da letra. Nao alarmista.
- ASCII puro nos arquivos novos. Nao usar setas ou bullets unicode.

## Passo 1 - PostureGauge

Criar app/components/posture-gauge.tsx com:
- Props: { score: number, grade: string, degraded?: boolean, size?: number (default 160) }
- Cor por score: 90+ #22c55e, 75-89 #3b82f6, 60-74 #eab308, 40-59 #f97316, <40 #ef4444
- Centro: grade letra grande (~size*0.4) em branco, score pequeno (size*0.13) /100 em cinza
- Footer: se degraded, texto Partial data em gray-500. Senao, texto Repo posture em cor do gauge.

## Passo 2 - PostureCard

Criar app/components/posture-card.tsx com:
- Props: { posture: PostureResult } (importar tipo de @/lib/posture)
- Layout: container igual RiskCard. Esquerda PostureGauge, direita conteudo.
- Conteudo direita:
  - Header: Repo posture (mesma vibe do Where the score comes from)
  - 3 mini-bars: itera posture.breakdown, cada um com label + points/pointsMax + barra
  - Quick wins: se posture.quickWins.length > 0, mostra Quick wins to improve + ul com items. Senao, mostra No quick wins remaining em cinza.

## Passo 3 - Wirar em page.tsx

Em app/dashboard/scan/[owner]/[repo]/page.tsx:
1. Adicionar import: import type { PostureResult } from @/lib/posture
2. Adicionar import: import { PostureCard } from @/app/components/posture-card
3. Extender ScanResultFull: + posture?: PostureResult
4. Renderizar abaixo do RiskCard: {result.posture && <PostureCard posture={result.posture} />}

## Passo 4 - Build local

npm run build verde. Zero TypeScript errors esperados (PostureResult tipado, todas props batendo).

## Passo 5 - Commit + push

git add app/components/posture-gauge.tsx app/components/posture-card.tsx app/dashboard/scan/[owner]/[repo]/page.tsx
git commit -m feat(posture): UI card with gauge, breakdown, and quick wins (C3)
git push

## Passo 6 - Smoke visual pos-deploy

1. Apos Vercel deploy verde, abrir https://repoguard-chi.vercel.app
2. Logar e rodar scan em silviooerudon/repoguard
3. Esperado: PostureCard aparece abaixo do RiskCard, mostra letra F (vermelho), score 25, 3 mini-bars (todas baixas pra esse repo), 4 quick wins listados
4. Confirmar: degraded badge nao aparece (smoke C1 confirmou degraded false)

DoD da C3: PostureCard renderizado em prod sem erros, breakdown e quick wins visiveis.

## Riscos

- Risco: tipo PostureResult nao exporta algum campo que eu uso. Mitigacao: handoff confirma exports de PostureGrade, PostureCategoryId, PostureSignal, PostureCategoryBreakdown, QuickWin, PostureResult. Cobre tudo que vou tocar.
- Risco: PostureCard estoura container em mobile. Mitigacao: mesmo flex md:flex-row do RiskCard - empilha em mobile, lado-a-lado em desktop.
- Risco: scans antigos no historico (/scan/view/[id]) parecem inconsistentes sem posture. Mitigacao: aceito - historico ja nao mostra risk score tambem. Tarefa futura unifica ambos.

## Backlog vivo atualizado

- Mojibake em components - segue (linhas 95 page.tsx scan, 78 e 110 view/[id])
- quickwins_len=4 vs esperado 5 - investigar logica
- /scan/view/[id] nao mostra risk nem posture - escopo futuro consolidar
- Posture C1 deferidos seguem
