export type DependencyFinding = {
  package: string;
  version: string;
  severity: "critical" | "high" | "moderate" | "low";
  title: string;
  ghsa: string | null;
  vulnerable_versions: string;
  cvss_score: number | null;
  url: string;
};