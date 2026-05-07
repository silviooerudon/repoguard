// IAM Admin Equivalents detectors (D4, Categoria 3)
// Cobertura "table stakes" - nao e diferenciador, mas fecha buraco obvio
// vs Checkov / Trivy.
//
// 3 detectors:
//   iam-action-resource-wildcard   critical (Action: * OR many service:* + Resource: *)
//   iam-sensitive-service-wildcard high     (sensitive service action + Resource: *)
//   iam-principal-wildcard         critical (resource policy with Principal: * + no Condition)

import type { IAMFinding, IAMSeverity, IAMCategoryId } from "./iam"
import type { PrivescStatement } from "./iam-privesc"

// Re-export the same statement shape under a category-appropriate name.
// Same structure - just naming for readability at call site.
export type AdminStatement = PrivescStatement

const SENSITIVE_SERVICES = ["iam", "kms", "secretsmanager", "sts"]

const SERVICE_WILDCARD_THRESHOLD = 3 // 3+ "service:*" with Resource:* counts as quasi-admin

function isAllow(stmt: AdminStatement): boolean {
  if (typeof stmt.effect !== "string") return false
  return stmt.effect.toLowerCase() === "allow"
}

function actionsLower(stmt: AdminStatement): string[] {
  return stmt.actions.map((a) => a.toLowerCase())
}

function resourcesLower(stmt: AdminStatement): string[] {
  return stmt.resources.map((r) => r.toLowerCase())
}

function hasNotAction(stmt: AdminStatement): boolean {
  return stmt.actions.some((a) => a.startsWith("!"))
}

function hasWildcardResource(stmt: AdminStatement): boolean {
  return resourcesLower(stmt).some((r) => r === "*")
}

function hasFullActionWildcard(stmt: AdminStatement): boolean {
  return actionsLower(stmt).some((a) => a === "*")
}

function countServiceWildcards(stmt: AdminStatement): number {
  // Count entries like "ec2:*", "s3:*" - service wildcards but not full "*".
  return actionsLower(stmt).filter(
    (a) => a !== "*" && a.endsWith(":*"),
  ).length
}

function principalWildcardKind(principal: unknown): "none" | "string" | "aws" {
  // "*" string => string wildcard
  // { AWS: "*" } or { AWS: ["*"] } => aws wildcard
  // { Service: ... } or { AWS: "<arn>" } => not wildcard
  if (principal === "*") return "string"
  if (principal === null || typeof principal !== "object") return "none"
  const p = principal as Record<string, unknown>

  // HCL shape: { hcl: ["AWS:*", ...] }
  if (Array.isArray(p.hcl)) {
    for (const s of p.hcl) {
      if (typeof s !== "string") continue
      // Format is "<Type>:<identifier>"
      const idx = s.indexOf(":")
      if (idx < 0) continue
      const type = s.slice(0, idx)
      const ident = s.slice(idx + 1).trim()
      if (type.toLowerCase() === "aws" && ident === "*") return "aws"
    }
    return "none"
  }

  // JSON: examine each known key
  for (const [key, v] of Object.entries(p)) {
    const lk = key.toLowerCase()
    if (lk !== "aws") continue
    if (v === "*") return "aws"
    if (Array.isArray(v) && v.some((x) => x === "*")) return "aws"
  }
  return "none"
}

function makeAdminFinding(
  ruleId: string,
  ruleName: string,
  severity: IAMSeverity,
  description: string,
  remediation: string,
  filePath: string,
  stmt: AdminStatement,
): IAMFinding {
  const category: IAMCategoryId = "admin"
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

// ---------- Detectors ----------

function detectActionResourceWildcard(
  stmt: AdminStatement,
  filePath: string,
): IAMFinding[] {
  if (!isAllow(stmt)) return []
  if (hasNotAction(stmt)) return []
  if (!hasWildcardResource(stmt)) return []

  const fullWildcard = hasFullActionWildcard(stmt)
  const serviceWildcardCount = countServiceWildcards(stmt)

  if (fullWildcard) {
    return [
      makeAdminFinding(
        "iam-action-resource-wildcard",
        "Allow with Action: * and Resource: *",
        "critical",
        "This statement grants every AWS action on every resource. It is equivalent to AdministratorAccess and bypasses all permission boundaries by design.",
        "If administrative access is genuinely required, attach the AWS managed AdministratorAccess policy explicitly so the intent is auditable. Otherwise replace Action: * with a specific list of actions and constrain Resource to the ARNs that need access.",
        filePath,
        stmt,
      ),
    ]
  }

  if (serviceWildcardCount >= SERVICE_WILDCARD_THRESHOLD) {
    return [
      makeAdminFinding(
        "iam-action-resource-wildcard",
        "Allow with multiple service-level wildcards and Resource: *",
        "critical",
        "This statement grants " + serviceWildcardCount + " service-wide action wildcards (e.g. ec2:*, s3:*) on every resource. In practice this is admin-equivalent for cloud workloads - any of those services can be fully manipulated, including data exfiltration and infrastructure destruction.",
        "Constrain each action wildcard to the specific operations actually needed (e.g. s3:GetObject instead of s3:*) and restrict Resource to specific ARNs. If broad access really is required, use the AWS managed PowerUserAccess policy explicitly.",
        filePath,
        stmt,
      ),
    ]
  }

  return []
}

function detectSensitiveServiceWildcard(
  stmt: AdminStatement,
  filePath: string,
): IAMFinding[] {
  if (!isAllow(stmt)) return []
  if (hasNotAction(stmt)) return []
  if (!hasWildcardResource(stmt)) return []
  if (hasFullActionWildcard(stmt)) return [] // already caught by action-resource-wildcard

  const matched = new Set<string>()
  for (const a of actionsLower(stmt)) {
    for (const svc of SENSITIVE_SERVICES) {
      if (a === svc + ":*" || a.startsWith(svc + ":")) {
        matched.add(svc)
      }
    }
  }
  if (matched.size === 0) return []

  const list = Array.from(matched).sort().join(", ")
  return [
    makeAdminFinding(
      "iam-sensitive-service-wildcard",
      "Sensitive service action with Resource: *",
      "high",
      "This statement grants action(s) on sensitive AWS service(s) (" + list + ") with Resource: *. These services control identity, encryption keys, secrets, or federation - granting wildcard resource access to them is rarely justified and expands blast radius significantly.",
      "Restrict Resource to the specific ARNs (key, secret, role, policy) that this principal needs. If the action set is narrow (e.g. only kms:Decrypt on one key), pin Resource to that exact ARN.",
      filePath,
      stmt,
    ),
  ]
}

function detectPrincipalWildcard(
  stmt: AdminStatement,
  filePath: string,
): IAMFinding[] {
  if (!isAllow(stmt)) return []
  const kind = principalWildcardKind(stmt.principal)
  if (kind === "none") return []
  if (stmt.conditions !== null && stmt.conditions !== undefined) return []

  const desc = kind === "string"
    ? "Principal is the literal '*', meaning any AWS principal anywhere can perform the allowed actions on this resource."
    : "Principal is { AWS: '*' }, meaning any IAM principal in any AWS account can perform the allowed actions on this resource."

  return [
    makeAdminFinding(
      "iam-principal-wildcard",
      "Resource policy allows wildcard Principal without Condition",
      "critical",
      desc + " Without a Condition (e.g. aws:SourceAccount, aws:PrincipalOrgID, aws:SourceArn), this exposes the resource to the entire internet of AWS accounts.",
      "Replace the wildcard Principal with the specific account IDs, role ARNs, or service principals that legitimately need access. If a wildcard is intentionally needed (e.g. public S3 bucket for static hosting), add a Condition that constrains the access pattern.",
      filePath,
      stmt,
    ),
  ]
}

// ---------- Public entry point ----------

/**
 * Detects admin-equivalent patterns across a single file's statements.
 * Called once per scanned file from assessIAM.
 */
export function detectAdminEquivalents(
  stmts: AdminStatement[],
  filePath: string,
): IAMFinding[] {
  const findings: IAMFinding[] = []
  for (const s of stmts) {
    findings.push(...detectActionResourceWildcard(s, filePath))
    findings.push(...detectSensitiveServiceWildcard(s, filePath))
    findings.push(...detectPrincipalWildcard(s, filePath))
  }
  return findings
}
