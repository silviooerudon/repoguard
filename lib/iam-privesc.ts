// IAM Privilege Escalation detectors (D3, Categoria 2)
// Padrao Rhino / IGA: cruza statements ao inves de auditar policy isolada.
//
// 5 detectors (severity per plan-iam-d1-scope.md):
//   iam-passrole-wildcard                  critical (per-statement)
//   iam-passrole-with-create-compute       critical (file-level)
//   iam-self-managing                      critical (per-statement, Resource: * only)
//   iam-assume-role-no-condition           high     (per-statement)
//   iam-not-action-allow                   high     (per-statement, Allow only)

import type { IAMFinding, IAMSeverity, IAMCategoryId } from "./iam"

// Statement shape consumed by these detectors. Mirror of the private
// IamStatement in lib/iam.ts. Kept structurally compatible so callers
// can pass IamStatement values directly.
export type PrivescStatement = {
  effect: string | null
  principal: unknown
  actions: string[]
  resources: string[]
  conditions: unknown
  sourceLine: number | null
  rawSnippet: string
}

const CREATE_COMPUTE_ACTIONS = [
  "lambda:createfunction",
  "ec2:runinstances",
  "ecs:runtask",
  "glue:createjob",
]

const SELF_MANAGING_ACTIONS = [
  "iam:createpolicyversion",
  "iam:setdefaultpolicyversion",
  "iam:attachrolepolicy",
  "iam:putrolepolicy",
]

function isAllow(stmt: PrivescStatement): boolean {
  if (typeof stmt.effect !== "string") return false
  return stmt.effect.toLowerCase() === "allow"
}

function actionsLower(stmt: PrivescStatement): string[] {
  return stmt.actions.map((a) => a.toLowerCase())
}

function resourcesLower(stmt: PrivescStatement): string[] {
  return stmt.resources.map((r) => r.toLowerCase())
}

function hasNotAction(stmt: PrivescStatement): boolean {
  // Parsers in lib/iam.ts prefix NotAction entries with "!" in stmt.actions.
  return stmt.actions.some((a) => a.startsWith("!"))
}

function actionMatches(action: string, target: string): boolean {
  // target is fully qualified lowercase (e.g. "iam:passrole").
  // action may be a wildcard pattern like "iam:*" or "*".
  const a = action.toLowerCase()
  if (a === "*") return true
  if (a === target) return true
  if (a.endsWith("*")) {
    const prefix = a.slice(0, -1)
    return target.startsWith(prefix)
  }
  return false
}

function statementGrantsAction(stmt: PrivescStatement, target: string): boolean {
  if (!isAllow(stmt)) return false
  if (hasNotAction(stmt)) return false
  return actionsLower(stmt).some((a) => actionMatches(a, target))
}

function hasWildcardResource(stmt: PrivescStatement): boolean {
  return resourcesLower(stmt).some((r) => r === "*")
}

function principalMatchesWildcard(principal: unknown): boolean {
  if (principal === "*") return true
  if (principal === null || typeof principal !== "object") return false
  const p = principal as Record<string, unknown>
  // HCL shape from extractHclStatementBlocks: { hcl: ["AWS:*", ...] }
  if (Array.isArray(p.hcl)) {
    return p.hcl.some((s) => typeof s === "string" && /:\*\s*$/.test(s))
  }
  // JSON shape: { AWS: "*" } or { AWS: ["*"] } or { Service: "...", AWS: "*" }
  for (const v of Object.values(p)) {
    if (v === "*") return true
    if (Array.isArray(v) && v.some((x) => x === "*")) return true
  }
  return false
}

function makePrivescFinding(
  ruleId: string,
  ruleName: string,
  severity: IAMSeverity,
  description: string,
  remediation: string,
  filePath: string,
  stmt: PrivescStatement,
): IAMFinding {
  const category: IAMCategoryId = "privesc"
  return {
    ruleId,
    ruleName,
    severity,
    category,
    description,
    remediation,
    filePath,
    lineNumber: stmt.sourceLine,
    evidence: stmt.rawSnippet,
  }
}

// ---------- Per-statement detectors ----------

function detectPassRoleWildcard(
  stmt: PrivescStatement,
  filePath: string,
): IAMFinding[] {
  if (!statementGrantsAction(stmt, "iam:passrole")) return []
  if (!hasWildcardResource(stmt)) return []
  return [
    makePrivescFinding(
      "iam-passrole-wildcard",
      "iam:PassRole granted on Resource: *",
      "critical",
      "This statement allows passing any IAM role to AWS services. Combined with a service that runs custom code (Lambda, EC2, ECS, Glue), this is a documented privilege escalation path: the principal can pass a more privileged role to compute they create.",
      "Restrict Resource to the exact role ARNs that this principal legitimately needs to pass. Use a Condition with iam:PassedToService to further constrain which services can receive the role.",
      filePath,
      stmt,
    ),
  ]
}

function detectSelfManaging(
  stmt: PrivescStatement,
  filePath: string,
): IAMFinding[] {
  if (!isAllow(stmt)) return []
  if (hasNotAction(stmt)) return []
  if (!hasWildcardResource(stmt)) return []
  const acts = actionsLower(stmt)
  const matched = SELF_MANAGING_ACTIONS.find((sm) =>
    acts.some((a) => actionMatches(a, sm)),
  )
  if (!matched) return []
  return [
    makePrivescFinding(
      "iam-self-managing",
      "Policy can modify IAM policies on Resource: *",
      "critical",
      "This statement allows " + matched + " on any resource. A principal with this permission can attach AdministratorAccess to itself or to any role - effectively becoming an admin regardless of its initial scope.",
      "Restrict Resource to a specific role ARN that legitimately needs self-management, or remove the IAM-mutating action entirely. IAM permission management should be handled by a dedicated, highly restricted role.",
      filePath,
      stmt,
    ),
  ]
}

function detectAssumeRoleNoCondition(
  stmt: PrivescStatement,
  filePath: string,
): IAMFinding[] {
  if (!statementGrantsAction(stmt, "sts:assumerole")) return []
  if (stmt.conditions !== null && stmt.conditions !== undefined) return []
  const wildcardResource = hasWildcardResource(stmt)
  const wildcardPrincipal = principalMatchesWildcard(stmt.principal)
  if (!wildcardResource && !wildcardPrincipal) return []
  return [
    makePrivescFinding(
      "iam-assume-role-no-condition",
      "sts:AssumeRole allowed without a Condition",
      "high",
      "This trust relationship allows AssumeRole with a wildcard principal or resource and no Condition block. Any AWS account can attempt to assume this role.",
      "Add a Condition (e.g. aws:SourceAccount, aws:SourceArn, or sts:ExternalId) and remove wildcards from Principal/Resource.",
      filePath,
      stmt,
    ),
  ]
}

function detectNotActionAllow(
  stmt: PrivescStatement,
  filePath: string,
): IAMFinding[] {
  if (!isAllow(stmt)) return []
  if (!hasNotAction(stmt)) return []
  return [
    makePrivescFinding(
      "iam-not-action-allow",
      "Statement uses Allow with NotAction (inverted logic)",
      "high",
      "Allow + NotAction grants every action except the listed ones. This is rarely the author's actual intent and almost always grants more permissions than expected, including future AWS actions added after the policy was written.",
      "Rewrite the statement using Allow with an explicit Action list that enumerates only the permissions actually required. Reserve NotAction for Deny statements.",
      filePath,
      stmt,
    ),
  ]
}

// ---------- File-level detector ----------

function statementGrantsAnyCreateCompute(stmt: PrivescStatement): boolean {
  if (!isAllow(stmt)) return false
  if (hasNotAction(stmt)) return false
  const acts = actionsLower(stmt)
  return CREATE_COMPUTE_ACTIONS.some((cc) =>
    acts.some((a) => actionMatches(a, cc)),
  )
}

function detectPassRoleWithCreateCompute(
  stmts: PrivescStatement[],
  filePath: string,
): IAMFinding[] {
  const passRoleStmts = stmts.filter(
    (s) => statementGrantsAction(s, "iam:passrole"),
  )
  if (passRoleStmts.length === 0) return []
  const createComputeStmts = stmts.filter(statementGrantsAnyCreateCompute)
  if (createComputeStmts.length === 0) return []

  const matchedActions = new Set<string>()
  for (const cc of createComputeStmts) {
    for (const a of actionsLower(cc)) {
      for (const target of CREATE_COMPUTE_ACTIONS) {
        if (actionMatches(a, target)) matchedActions.add(target)
      }
    }
  }
  const matchedList = Array.from(matchedActions).join(", ")

  // Anchor one finding per PassRole statement (most actionable line to fix).
  const findings: IAMFinding[] = []
  for (const pr of passRoleStmts) {
    findings.push(
      makePrivescFinding(
        "iam-passrole-with-create-compute",
        "iam:PassRole combined with compute creation in the same file",
        "critical",
        "This file grants iam:PassRole and also grants action(s) that create new compute (" + matchedList + "). Together they form a documented AWS privilege-escalation path: the principal can launch new compute and attach a more privileged role to it, bypassing its own permission boundary.",
        "Split these permissions across two separate roles, or constrain iam:PassRole to specific role ARNs and add a Condition with iam:PassedToService limiting which compute services can receive each role.",
        filePath,
        pr,
      ),
    )
  }
  return findings
}

// ---------- Public entry point ----------

/**
 * Detects privilege escalation patterns across a single file's statements.
 * Called once per scanned file from assessIAM.
 */
export function detectPrivilegeEscalation(
  stmts: PrivescStatement[],
  filePath: string,
): IAMFinding[] {
  const findings: IAMFinding[] = []
  for (const s of stmts) {
    findings.push(...detectPassRoleWildcard(s, filePath))
    findings.push(...detectSelfManaging(s, filePath))
    findings.push(...detectAssumeRoleNoCondition(s, filePath))
    findings.push(...detectNotActionAllow(s, filePath))
  }
  findings.push(...detectPassRoleWithCreateCompute(stmts, filePath))
  return findings
}
