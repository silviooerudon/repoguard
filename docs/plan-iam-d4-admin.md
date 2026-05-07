# Plano - RepoGuard, Sessao D4 (IAM Admin Equivalents detectors)

## Contexto

Bloco 2 Item 2, Categoria 3 do IAM Risk Scanner. D2 fechou Categoria 1
(OIDC, 4 detectores). D3 fechou Categoria 2 (privilege escalation, 5
detectores). D3.1 corrigiu parser Terraform heredoc (bug bloqueante que
deixava D2/D3 sem cobertura real em prod). D4 fecha Categoria 3.

D4 = 3 detectores, sotaque "table stakes". Nao e diferenciador (Checkov
e Trivy fazem isso bem) mas e cobertura minima pra nao ter buraco obvio.
Ainda assim, com a base de parser que ja temos, o custo marginal e baixo
e fechar Categoria 3 fecha o backend do IAM Scanner inteiro.

## Escopo cravado em D1 (nao revisitar)

3 detectores, severities conforme plan-iam-d1-scope.md:

| ID | Detec | Severity |
|----|-------|----------|
| iam-action-resource-wildcard | Action: * + Resource: * em Allow | critical |
| iam-sensitive-service-wildcard | Resource: * com action iam:* / kms:* / secretsmanager:* / sts:* | high |
| iam-principal-wildcard | Resource policy com Principal: * ou AWS: * sem Condition | critical |

## Decisoes de escopo de D4

### iam-action-resource-wildcard

Pega o caso classico de admin equivalent: Allow + Action: * + Resource: *.
Validado contra TerraGoat - iam.tf tem essa exata forma com Action ec2:*,
s3:*, lambda:*, cloudwatch:* e Resource: *. Mas Action: ec2:* nao e
exatamente Action: *.

Decisao: detector cobre os DOIS casos:
1. Action contem literal "*" (admin total)
2. Action contem multiplos service-wide wildcards (>=3 de "service:*")
   E Resource: *

Caso 2 e quase-admin na pratica. EC2 + S3 + Lambda + CloudWatch sem
restricao de recurso = admin de fato pra workloads cloud. Tradeoff:
pode dar falso positivo em policies legitimas de admin de plataforma,
mas e raro - admins reais usam AdministratorAccess managed policy.

### iam-sensitive-service-wildcard

Resource: * combinado com action de servico sensivel (iam, kms,
secretsmanager, sts). Captura casos onde o engenheiro restringiu por
servico mas esqueceu de restringir Resource.

Lista de servicos sensiveis (cravada, sem expansao no MVP):
- iam (manipula identidade e permissao)
- kms (chaves de criptografia)
- secretsmanager (segredos)
- sts (assume role / federation)

Severity high (nao critical) porque nem sempre e privesc imediato -
depende do que o servico permite. Critical fica reservado pro
action-resource-wildcard que e quase sempre admin.

### iam-principal-wildcard

Resource policy (S3 bucket policy, KMS key policy, SNS topic policy,
SQS queue policy, etc.) com Principal: * ou Principal: { AWS: * } sem
Condition. Significa que QUALQUER principal de QUALQUER conta AWS
pode usar o recurso.

Detecta:
- Effect: Allow
- Principal e wildcard (string "*", { AWS: "*" }, { AWS: ["*"] })
- Conditions ausente

Ignora:
- Principal: { Service: "..." } - servico AWS especifico, e padrao
- Principal: { AWS: "arn:aws:iam::123:role/x" } - especifico
- Tem Condition (mesmo que fraca - whitelist de IP via Condition existe)

Sobreposicao com iam-assume-role-no-condition (D3): aquele e especifico
pra sts:AssumeRole. Esse e geral pra qualquer resource policy. Possivel
dupla-deteccao no caso de trust policy com Principal: * - aceitavel,
sao angulos diferentes do mesmo problema.

## Padrao tecnico (espelha D3)

Modulo separado lib/iam-admin.ts. Importado por lib/iam.ts. Wiring
identico ao D3:

```typescript
import { detectAdminEquivalents } from "./iam-admin"
// ...
findings.push(...detectPrivilegeEscalation(stmts, batch[j].path))
findings.push(...detectAdminEquivalents(stmts, batch[j].path))
```

Tipo PrivescStatement do D3 e re-exportado aqui como AdminStatement (ou
shared - decisao do Claude no momento da implementacao).

## Score impact

3 novos detectores. Em TerraGoat esperado:
- iam.tf: 1 finding iam-action-resource-wildcard (critical, -20)
- db-app.tf: 1 finding iam-action-resource-wildcard (critical, -20)
- score baseline 100 - 40 = 60 = level "high"

Pode ainda dar mais se outros .tf tiverem padrao similar. Validacao
sera via smoke-iam.ts apos implementacao - tem que sair de 0 findings
pra >= 2.

## Persistencia / UI / Migration

Zero mudanca. Migration 004 do D2 ja cobre tudo. UI fica pra D5.

## Sequencia D4

1. lib/iam-admin.ts com 3 detectores + helpers compartilhados
2. patch Python wiring em lib/iam.ts
3. npm run build
4. STOP HERE if build red
5. npx tsx scripts/smoke-iam.ts ..\terragoat-fixture\terraform\aws
6. STOP HERE if findings == 0 (significa bug, nao "TerraGoat = D4")
7. git add lib/iam.ts lib/iam-admin.ts scripts/patch-iam-d4.py docs/plan-iam-d4-admin.md
8. git commit -m "feat(iam): admin equivalent detectors (D4)"
9. git push
10. Smoke pos-deploy: scanear bridgecrewio/terragoat em prod logado,
    confirmar iam.findings nao vazio e iam.score < 100

## Nao revisitar

- 3 detectores acima exatamente
- Lista de servicos sensiveis em iam-sensitive-service-wildcard
  (iam/kms/secretsmanager/sts) cravada, expansao e backlog v2
- Severity por detector conforme plan D1
- Sem mudanca em UI / migration / persistencia
