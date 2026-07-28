export type CheckStatus = "pass" | "warning" | "fail" | "info";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface AuditCheck {
  id: string;
  category: string;
  title: string;
  status: CheckStatus;
  severity: Severity;
  evidence: string;
  recommendation?: string;
  weight: number;
}

export interface AuditCategory {
  id: string;
  title: string;
  score: number;
  checks: AuditCheck[];
}

export interface RedirectStep {
  url: string;
  status: number;
}

export interface SiteMetrics {
  responseTimeMs: number;
  htmlBytes: number;
  statusCode: number;
  redirects: number;
  scripts: number;
  thirdPartyScripts: number;
  images: number;
  stylesheets: number;
  forms: number;
  externalOrigins: number;
}

export interface RepositorySummary {
  repository: string;
  defaultBranch: string;
  commit: string;
  filesScanned: number;
  dependenciesChecked: number;
  vulnerabilities: number;
  checks: AuditCheck[];
  error?: string;
}

export interface ScanReport {
  reportVersion: 1;
  id: string;
  scannedAt: string;
  target: {
    requestedUrl: string;
    finalUrl: string;
    statusCode: number;
    redirects: RedirectStep[];
  };
  summary: {
    score: number;
    grade: string;
    passed: number;
    warnings: number;
    failed: number;
    informational: number;
  };
  categories: AuditCategory[];
  metrics: SiteMetrics;
  technologies: string[];
  repository?: RepositorySummary;
  limitations: string[];
}

export interface FetchResult {
  requestedUrl: URL;
  finalUrl: URL;
  response: Response;
  html: string;
  bytes: number;
  durationMs: number;
  redirects: RedirectStep[];
}
