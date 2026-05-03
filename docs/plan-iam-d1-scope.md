# Plano - RepoGuard, Sessao D1 (IAM Risk Scanner - Escopo)

## Contexto

Bloco 2 Item 2 do roadmap. Posture Score (Item 1) fechado em maio 2026.
IAM Risk Scanner e a unfair advantage do RepoGuard: 10 anos de IAM/IGA do
Silvio (SailPoint/CyberArk) em uma SaaS feature que o mercado de scanners
de repo nao executa bem.

D1 = recon + briefing. Sem codigo de detector. Padrao validado nas sessoes
B (suppressions) e C (posture): briefing markdown commitavel define escopo
antes de qualquer implementacao.

## Posicionamento de produto

> "Outros scanners flaggam wildcards. RepoGuard mostra o caminho de escalacao."

A linha acima e o angulo. Mercado atual:

- Checkov (1000+ regras) - faz wildcard checks comoditizados, nao cruza
  privilege escalation paths nem lida bem com OIDC trust weakness.
- Trivy (absorveu tfsec) - paridade Checkov em IaC genericas.
- Cloudsplaining - audita conta AWS viva, nao repo estatico.
- IAMActionHunter / CloudTracker - pentest de account vivo.
- IAM Policy Autopilot (AWS Labs) - gera policies, nao audita.
- Legitify - GitHub org config (MFA, branch protection), nao policy IAM.

Gap claro pra solo dev em SaaS brilhar:

1. GitHub OIDC + AWS trust policy weaknesses (vetor mais explorado em 2026,
   GhostAction / s1ngularity wave). Quase nenhum scanner de repo flagga bem.
2. Privilege escalation paths multi-statement (PassRole + create-compute,
   self-managing IAM). Territorio Rhino/IGA, raro em scanners de repo.
3. Logica invertida (NotAction/NotResource Allow). Classico de IGA review,
   raro em scanner.

## Recon do existente em lib/iac.ts

Inspecionado em D1. Cobertura IAM atual:

- gha-permissions-write-all: literal "permissions: write-all" - low overlap
- gha-pull-request-target-checkout-head: vetor diferente (code execution
  via PR), nao policy analysis
- Dockerfile rules: privilegio em container OS, nao cloud IAM

Conclusao: zero overlap com cloud IAM. Cobertura GH Actions e literal e
mininima. iac.ts fica como esta. IAM Scanner e detector novo em arquivo
proprio (lib/iam.ts).

## Decisoes de escopo (cravadas na D1)

### Provedores no MVP

- AWS IAM (Terraform .tf, CloudFormation .yml/.json, Serverless .yml,
  raw policy .json)
- AWS IAM em GitHub Actions trust policies (OIDC federation)

Fora do MVP (backlog): GCP service accounts, Azure Managed Identity,
Kubernetes RBAC. Razao: AWS tem maior densidade em repos de SaaS, OIDC
trust policy e o vetor 2026, e cobrir 1 provedor bem > 4 mal.

### Surface de deteccao

- Apenas arquivos IaC (estaticos), tipos: .tf, .yml, .yaml, .json em paths
  comuns de IaC.

Fora do MVP: codigo fonte que monta policy dinamicamente (boto3, AWS SDK
inline). Razao: regex em policy estatica = alta precisao; regex em codigo
fonte = falso-positivo garantido (vars, concat, factories). Exige AST
real, nao cabe em MVP. Backlog vivo.

### Detectores no MVP (12 detectores em 3 categorias)

#### Categoria 1 - GitHub OIDC trust weaknesses

Diferenciador #1. Vetor mais explorado em 2026 (GhostAction, s1ngularity).

| ID | Nome | Severidade |
|----|------|------------|
| iam-oidc-wildcard-repo | OIDC trust com sub: repo:org/*:* (wildcard de repo) | critical |
| iam-oidc-wildcard-ref | OIDC trust com sub: repo:org/repo:* (sem pin de ref/env) | high |
| iam-oidc-no-condition | OIDC trust sem Condition block | critical |
| iam-oidc-pull-request-trust | OIDC trust aceita sub: repo:*:pull_request | critical |

Detecao: arquivos .tf / .json / .yml com trust policy contendo
`Federated: ...token.actions.githubusercontent.com` ou
`Federated: ...oidc-provider/token.actions.githubusercontent.com`.

#### Categoria 2 - Privilege escalation patterns

Diferenciador #2. Sotaque IGA - cruza statements, nao olha policy isolada.

| ID | Nome | Severidade |
|----|------|------------|
| iam-passrole-wildcard | iam:PassRole com Resource: * | critical |
| iam-passrole-with-create-compute | iam:PassRole + (lambda:CreateFunction OR ec2:RunInstances OR ecs:RunTask OR glue:CreateJob) na mesma policy | critical |
| iam-self-managing | Policy permite iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion / iam:AttachRolePolicy / iam:PutRolePolicy em si mesma ou * | critical |
| iam-assume-role-no-condition | sts:AssumeRole Allow com Resource: * ou Principal: AWS: * sem Condition | high |
| iam-not-action-allow | Statement Allow com NotAction (logica invertida) | high |

Padrao Rhino: PassRole + create-compute = privilege escalation documentado
(role passada pra novo Lambda/EC2 = bypass de boundary do user atual).
Self-managing = role que pode mudar sua propria policy = admin de fato.

#### Categoria 3 - Admin equivalents (baseline)

Cobertura minima pra nao ter buraco obvio vs Checkov. Nao e diferenciador
mas e table stakes.

| ID | Nome | Severidade |
|----|------|------------|
| iam-action-resource-wildcard | Action: * + Resource: * em Allow | critical |
| iam-sensitive-service-wildcard | Resource: * com action iam:* / kms:* / secretsmanager:* / sts:* | high |
| iam-principal-wildcard | Resource policy com Principal: * ou AWS: * sem Condition | critical |

## Padrao tecnico (espelha Posture)

Assinatura da funcao principal (espelha assessPosture):

```typescript
// lib/iam.ts
export type IAMSeverity = "critical" | "high" | "medium" | "low";
export type IAMCategoryId = "oidc" | "privesc" | "admin";

export type IAMFinding = {
  ruleId: string;
  ruleName: string;
  severity: IAMSeverity;
  category: IAMCategoryId;
  description: string;
  remediation: string;
  filePath: string;
  lineNumber: number | null;
  evidence: string | null;  // statement snippet / matched text
};

export type IAMCategoryBreakdown = {
  id: IAMCategoryId;
  label: string;
  findings: number;
  highestSeverity: IAMSeverity | null;
};

export type IAMResult = {
  score: number;             // 0-100, 100 = clean
  level: "low" | "medium" | "high" | "critical";
  breakdown: IAMCategoryBreakdown[];
  findings: IAMFinding[];
  filesScanned: number;
  degraded: boolean;
};

export async function assessIAM(
  owner: string,
  repo: string,
  accessToken: string | null,
): Promise<IAMResult>;
```

### Score model (espelha posture, ajustado pra IAM)

Inicial 100. Cada finding deduz por severidade:

- critical: -20
- high: -10
- medium: -5
- low: -2

Cap inferior em 0. Level derivado:

- score >= 90: low
- score 70-89: medium
- score 50-69: high
- score < 50: critical

(Nao usa grade A-F como Posture pra evitar confusao visual: Posture e
"quao maduro o repo esta" - normal ter B/C. IAM e "quao explosivo o
risco" - normal alvo e ZERO. Level low/medium/high/critical mais
adequado.)

### Persistencia

Migration 004 (proxima na sequencia 001 risk / 002 suppressed / 003
posture). Adiciona em scans:

- iam_score INTEGER
- iam_level TEXT
- iam_breakdown JSONB
- iam_findings JSONB

Espelha exato o que Posture fez em 003.

### Wiring

- app/api/scan/[owner]/[repo]/route.ts: assessIAM entra no Promise.all
  como 5o detector (junto com scanRepo, suppressions fetch, riskScore,
  assessPosture).
- app/api/scan-public/[owner]/[repo]/route.ts: simetria.
- ScanResultFull (declarado em 2 paginas): adicionar iam?: IAMResult.

### UI (D-N futura)

IAMCard espelha PostureCard:

- Gauge com score (0-100, vermelho->verde)
- Level badge (low/medium/high/critical)
- Breakdown por categoria (oidc / privesc / admin) com count
- Lista expandivel de findings com evidence + remediation por finding

Renderizada em ambas as rotas (logada e publica) abaixo de PostureCard.

## O que NAO fica no MVP (backlog vivo)

- GCP, Azure, Kubernetes RBAC (provedores)
- Codigo fonte que monta policy dinamicamente
- AST parser de HCL/YAML (regex statement-by-statement no MVP)
- Toxic combinations cross-policy (fica pra v2 com graph analysis)
- IAM scan no historico de commits (history.ts)
- IAM scan no dashboard/scan/view/[id] (consolidacao de historico ja
  pendente pra Risk e Posture)
- Detalhe inline de qual condition fortifica OIDC trust (so flagga,
  nao sugere automacao)

## Nao revisitar (decisoes ja cravadas)

- Provedor AWS only no MVP
- Surface IaC files only no MVP
- 12 detectores acima exatamente, em 3 categorias acima
- Score model 100 - dedution, level low/medium/high/critical
- Migration 004 com iam_score / iam_level / iam_breakdown / iam_findings
- IAMCard espelha PostureCard

## Sequencia D2..Dn proposta

- D2: backend - lib/iam.ts com os 4 detectores OIDC (Categoria 1).
  Wiring nas duas rotas + migration 004 + smoke. Razao: OIDC e o
  diferenciador mais facil de provar valor em screenshot.
- D3: backend - 5 detectores Privilege escalation (Categoria 2).
  Mais regex-pesado, vale uma sessao propria.
- D4: backend - 3 detectores Admin equivalents (Categoria 3).
  Sessao curta, fecha categoria de baseline.
- D5: UI - IAMCard nas 2 paginas.
- D6: smoke + ajustes.

Pode condensar D3+D4 num batch grande se a regex for direta.

## Ligar ao Posture Score (pos-MVP)

Posture pode incluir um signal "iam-score-clean" que vale pontos quando
IAM score >= 90. Nao no MVP - acoplamento prematuro.

## Lessons importadas

- Build local antes de TODO push (regra 1)
- Schema migration ANTES do push do codigo (regra 10)
- ASCII puro em arquivos novos (regra 4 e 7)
- Padrao Python-via-tmp pra evitar mojibake em PowerShell (regra 4 e 5)
- LiteralPath em paths com colchetes (regra 8)
- Hard refresh em smoke pos-deploy (regra 9)

## Comando inicial da D2

cd D:/Projetos/repoguard
git pull --rebase
git status
git log --oneline -5

Se ultimo commit for o D1 deste plano, arrancar pelo lib/iam.ts com os
4 detectores OIDC.
