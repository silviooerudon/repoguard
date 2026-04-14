// Shared types for scan results

export type DependencyFinding = {
  package: string;
  version: string;
  severity: "critical" | "high" | "moderate" | "low";
  title: string;
  cve: string | null;
  patched_versions: string;
  url: string;
};