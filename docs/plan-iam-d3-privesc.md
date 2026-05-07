# Plano - RepoGuard, Sessao D3 (IAM Privilege Escalation detectors)

## Contexto

Bloco 2 Item 2, Categoria 2 do IAM Risk Scanner. D2 fechou Categoria 1
(4 detectores OIDC trust) em commit be3d547. D3 entrega Categoria 2 -
Privilege escalation patterns. 5 detectores, todos sotaque IGA / Rhino.

## Diferenciador

> "Outros scanners flaggam wildcards. RepoGuard mostra o caminho de
> escalacao."

Categoria 2 e o coracao da unfair advantage. Cruza statements ao inves
de auditar policy isolada. Padroes aqui sao territorio Rhino Security
Labs / IGA review, raros em scanners de repo (Checkov, Trivy).

## Escopo cravado em D1 (nao revisitar)

5 detectores, todos severity critical OU high conforme tabela do plan-iam-d1-scope.md:

| ID | Detec | Severity |
|----|-------|----------|
| iam-passrole-wildcard | iam:PassRole com Resource: * | critical |
| iam-passrole-with-create-compute | PassRole + (lambda:CreateFunction OR ec2:RunInstances OR ecs:RunTask OR glue:CreateJob) no mesmo arquivo | critical |
| iam-self-managing | iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion / iam:AttachRolePolicy / iam:PutRolePolicy em si mesma ou * | critical |
| iam-assume-role-no-condition | sts:AssumeRole Allow com Resource: * ou Principal: AWS: * sem Condition | high |
| iam-not-action-allow | Statement Allow com NotAction (logica invertida) | high |

## Decisoes de escopo de D3

### iam-passrole-with-create-compute - escopo file-level

Detecta PassRole + create-compute action no MESMO ARQUIVO, statements
separados ou nao. Razao:

- Same-statement (so 1 statement contendo ambos) e raro - boas praticas
  de IaC separam por recurso/servico
- File-level pega o caso comum: 1 role-policy.tf com statement A
  (PassRole *) e statement B (lambda:CreateFunction *)
- Ambos (cross-file) e backlog v2 - exige analise multi-arquivo de role,
  fora do MVP

Severity mantem critical conforme plan D1.

### Self-targeting em iam-self-managing

"Em si mesma" significa Resource contem o ARN da propria role/policy.
Como nao sabemos o ARN da role no MVP (nao executamos terraform plan),
detectamos via:

- Resource: * (cobre 100% dos casos)
- Resource contem ${aws_iam_role.<x>.arn} ou similar (heuristica fraca,
  pula no MVP - regex em var resolution e falso-positivo)

MVP cobre apenas Resource: *. ARN-self-reference vira backlog. Tradeoff
explicito: prefere falso-negativo a falso-positivo nesse detector,
porque self-managing wildcard e o caso real de exploitacao.

### NotAction Allow

Logica invertida classica de IGA: Allow + NotAction = "permitir tudo
exceto X actions". Quase sempre lateral movement/privesc disfarcado.

Detecta:
- Effect: Allow
- NotAction presente (com qualquer valor)

Ignora:
- Effect: Deny + NotAction (e padrao legitimo de "deny exceto admins")

## Tipos novos / mudancas no IamStatement

Inspecionar lib/iam.ts antes de escrever. Provaveis adicoes:

- Helper extractActionList(stmt) - normaliza Action: string | string[]
  pra lista. Provavel ja existir como normaliseStringList.
- Helper hasNotAction(stmt) - true se stmt.NotAction definido.
- Helper isAllow(stmt) - effect === "Allow" (case-insensitive).

Reaproveita parser de D2 inteiro: extractStatements, IamStatement,
makeFinding. Zero codigo novo de parsing.

## Wiring

`computeIAMResult` ja existe e roda detectOidcWeaknesses. D3 adiciona:

```typescript
const findings: IAMFinding[] = [
  ...detectOidcWeaknesses(statements, fileToStatements),
  ...detectPrivilegeEscalation(statements, fileToStatements),
]
```

Nova funcao detectPrivilegeEscalation recebe:
- statements: IamStatement[] (todos os statements de todos os arquivos)
- fileToStatements: Map<string, IamStatement[]> (pra detector file-level)

Se fileToStatements ainda nao existir em D2, criar agora (computeIAMResult
ja itera arquivos, basta agrupar antes de chamar detectores).

## Score impact

Score ja tem dedution em SEVERITY_DEDUCTION. Critical -20, high -10.
5 novos detectores podem facilmente zerar score em repo IaC tipico
com role permissiva. Esperado e correto. Level virara critical em
repos com 2+ critical findings (-40 = score 60 = high level, e com
3+ critical = critical level).

## Persistencia

Zero mudanca. Migration 004 ja tem iam_findings JSONB que aceita
qualquer detector novo. Migration 004 ja foi aplicada em D2.

## UI

Zero mudanca em D3. UI fica pra D5. Hoje findings sao expostos via
JSON da rota - smoke valida via curl ou Network tab.

## Sequencia D3

1. Inspecionar lib/iam.ts: confirmar IamStatement shape, makeFinding
   assinatura, computeIAMResult assinatura
2. Implementar 5 detectores em bloco unico em lib/iam.ts:
   - detectPrivilegeEscalation(statements, fileToStatements)
   - Se necessario, refatorar computeIAMResult pra produzir
     fileToStatements
3. npm run build local
4. STOP HERE if build red
5. git add lib/iam.ts docs/plan-iam-d3-privesc.md
6. git commit -m "feat(iam): privilege escalation detectors (D3)"
7. git push
8. Smoke pos-deploy: scanear um repo IaC com PassRole wildcard e
   verificar que iam.findings contem novo ruleId

## Nao revisitar

- 5 detectores acima exatamente
- file-level scope em iam-passrole-with-create-compute
- Resource: * only em iam-self-managing (ARN self-ref e backlog)
- Severity por detector conforme plan D1
- Sem mudanca em UI / migration / persistencia
