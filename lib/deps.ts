import type { DependencyFinding } from "./types";

export async function scanDependencies(
  owner: string,
  repo: string,
  accessToken: string
): Promise<DependencyFinding[]> {
  // 1. Buscar package.json do repo
  const pkgRes = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/package.json`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github.v3.raw",
      },
    }
  );

  if (pkgRes.status === 404) return []; // não é projeto Node
  if (!pkgRes.ok) throw new Error(`GitHub API error: ${pkgRes.status}`);

  const pkgJson = await pkgRes.json();

  // 2. Montar payload pro npm audit
  const allDeps = {
    ...(pkgJson.dependencies || {}),
    ...(pkgJson.devDependencies || {}),
  };

  const packageNames = Object.keys(allDeps).slice(0, 500); // cap de segurança
  if (packageNames.length === 0) return [];

  const auditPayload: Record<string, string[]> = {};
  for (const name of packageNames) {
    const version = allDeps[name].replace(/[^\d.]/g, ""); // remove ^ ~ etc
    if (version) auditPayload[name] = [version];
  }

  // 3. Chamar npm audit API
  const auditRes = await fetch(
    "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(auditPayload),
    }
  );

  if (!auditRes.ok) throw new Error(`npm audit error: ${auditRes.status}`);

  const advisories = await auditRes.json();

  // 4. Parsear resposta
  const findings: DependencyFinding[] = [];
  for (const [pkgName, advList] of Object.entries(advisories)) {
    if (!Array.isArray(advList)) continue;
    for (const adv of advList as Array<{
      severity: string;
      title: string;
      cves: string[];
      vulnerable_versions: string;
      patched_versions: string;
      url: string;
    }>) {
      findings.push({
        package: pkgName,
        version: auditPayload[pkgName][0],
        severity: adv.severity as DependencyFinding["severity"],
        title: adv.title,
        cve: adv.cves?.[0] || null,
        patched_versions: adv.patched_versions,
        url: adv.url,
      });
    }
  }

  return findings;
}