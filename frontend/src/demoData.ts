import type { ScanResultsResponse, ScanStatusResponse } from "./types";

// Shown when the API is unreachable (e.g. this dashboard is deployed
// standalone on GitHub Pages with no backend running). Lets a live demo
// still show the intended UI, clearly labeled as sample data.
export const DEMO_TARGET = "demo.example.com";

export const DEMO_STATUS: ScanStatusResponse = {
  scan_id: "demo-scan-0001",
  target: DEMO_TARGET,
  profile: "web",
  overall_status: "completed",
  created_at: "2026-09-01T10:00:00Z",
  updated_at: "2026-09-01T10:00:45Z",
  scanners: [
    { tool: "nuclei", status: "completed", findings_count: 4, simulated: true, started_at: null, finished_at: null, error: null },
    { tool: "zap", status: "completed", findings_count: 4, simulated: true, started_at: null, finished_at: null, error: null },
    { tool: "nikto", status: "completed", findings_count: 3, simulated: true, started_at: null, finished_at: null, error: null },
  ],
};

export const DEMO_RESULTS: ScanResultsResponse = {
  scan_id: "demo-scan-0001",
  target: DEMO_TARGET,
  overall_status: "completed",
  severity_distribution: { critical: 0, high: 2, medium: 4, low: 5, info: 0 },
  duplicate_groups: 2,
  raw_findings: [
    { id: "f1", tool: "nuclei", target: DEMO_TARGET, vulnerability: "SQL Injection", severity: "medium", description: "Unescaped input in a query parameter.", evidence: "GET /products?id=1'", reference: "CWE-89" },
    { id: "f2", tool: "zap", target: DEMO_TARGET, vulnerability: "SQL Injection", severity: "high", description: "Confirmed boolean-based blind SQL injection.", evidence: "id=1 AND 1=1 vs 1=2", reference: "CWE-89" },
    { id: "f3", tool: "nuclei", target: DEMO_TARGET, vulnerability: "Missing Security Headers", severity: "low", description: "CSP / X-Frame-Options absent.", evidence: "HEAD / -> no CSP", reference: null },
    { id: "f4", tool: "zap", target: DEMO_TARGET, vulnerability: "Missing Security Headers", severity: "low", description: "CSP absent across scanned URLs.", evidence: "12/12 responses missing CSP", reference: null },
    { id: "f5", tool: "nikto", target: DEMO_TARGET, vulnerability: "Missing Security Headers", severity: "low", description: "X-Content-Type-Options not set.", evidence: "header absent", reference: null },
    { id: "f6", tool: "zap", target: DEMO_TARGET, vulnerability: "Cross-Site Scripting (Reflected)", severity: "medium", description: "Reflected input without encoding.", evidence: "/search?q=<script>", reference: "CWE-79" },
    { id: "f7", tool: "nikto", target: DEMO_TARGET, vulnerability: "Outdated Server Software", severity: "medium", description: "Server banner discloses an EOL version.", evidence: "Server: nginx/1.18.0", reference: null },
  ],
  correlated_findings: [
    { correlation_id: "c1", target: DEMO_TARGET, vulnerability: "SQL Injection", severity: "high", confidence: 70, contributing_tools: ["nuclei", "zap"], conflicting_severity: true, description: "Unescaped input in a query parameter.", evidence: ["GET /products?id=1'", "id=1 AND 1=1 vs 1=2"], reference: "CWE-89", source_finding_ids: ["f1", "f2"] },
    { correlation_id: "c2", target: DEMO_TARGET, vulnerability: "Missing Security Headers", severity: "low", confidence: 95, contributing_tools: ["nikto", "nuclei", "zap"], conflicting_severity: false, description: "CSP / X-Frame-Options absent.", evidence: ["HEAD / -> no CSP", "12/12 responses missing CSP", "header absent"], reference: null, source_finding_ids: ["f3", "f4", "f5"] },
    { correlation_id: "c3", target: DEMO_TARGET, vulnerability: "Cross-Site Scripting (Reflected)", severity: "medium", confidence: 45, contributing_tools: ["zap"], conflicting_severity: false, description: "Reflected input without encoding.", evidence: ["/search?q=<script>"], reference: "CWE-79", source_finding_ids: ["f6"] },
    { correlation_id: "c4", target: DEMO_TARGET, vulnerability: "Outdated Server Software", severity: "medium", confidence: 45, contributing_tools: ["nikto"], conflicting_severity: false, description: "Server banner discloses an EOL version.", evidence: ["Server: nginx/1.18.0"], reference: null, source_finding_ids: ["f7"] },
  ],
};
