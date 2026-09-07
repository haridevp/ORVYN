import type { ScanResultsResponse, ScanStatusResponse } from "./types";

export const DEMO_TARGET = "scanme.sh";

export const DEMO_STATUS: ScanStatusResponse = {
  scan_id: "demo-scan-0001",
  target: DEMO_TARGET,
  profile: "web",
  overall_status: "completed",
  progress_pct: 100,
  eta_seconds: 0,
  elapsed_seconds: 45,
  live_findings: [],
  findings_count: 53,
  created_at: "2026-09-01T10:00:00Z",
  updated_at: "2026-09-01T10:00:45Z",
  in_scope: ["*.scanme.sh", "scanme.sh"],
  out_of_scope: ["auth.scanme.sh", "admin.*"],
  scanners: [
    { tool: "nuclei", status: "completed", findings_count: 25, simulated: true, started_at: null, finished_at: null, error: null },
    { tool: "zap", status: "completed", findings_count: 3, simulated: true, started_at: null, finished_at: null, error: null },
    { tool: "nikto", status: "completed", findings_count: 10, simulated: true, started_at: null, finished_at: null, error: null },
    { tool: "whatweb", status: "completed", findings_count: 2, simulated: true, started_at: null, finished_at: null, error: null },
    { tool: "nmap", status: "completed", findings_count: 2, simulated: true, started_at: null, finished_at: null, error: null },
    { tool: "sslyze", status: "completed", findings_count: 3, simulated: true, started_at: null, finished_at: null, error: null },
    { tool: "wapiti", status: "completed", findings_count: 10, simulated: true, started_at: null, finished_at: null, error: null },
  ],
  logs: [
    "[10:00:01] [system] Job demo-scan-0001 queued for target scanme.sh with 7 engines: nuclei, zap, nikto, whatweb, nmap, sslyze, wapiti",
    "[10:00:01] [nuclei] Scanner worker started in [REAL ENGINE] mode for target: scanme.sh",
    "[10:00:02] [nmap] Running port discovery on 22, 80, 443",
    "[10:00:05] [whatweb] Identified web stack: Apache/2.4.41, OpenSSL/1.1.1f, PHP/7.4.3",
    "[10:00:15] [sslyze] Discovered deprecated protocol: TLS 1.0 & TLS 1.1 enabled",
    "[10:00:22] [wapiti] Missing security headers: Content-Security-Policy & X-Frame-Options",
    "[10:00:30] [nikto] Server banner discloses outdated software: nginx/1.18.0",
    "[10:00:45] [system] Consolidated 53 findings into 28 correlated vulnerability groups.",
  ],
};

export const DEMO_RESULTS: ScanResultsResponse = {
  scan_id: "demo-scan-0001",
  target: DEMO_TARGET,
  overall_status: "completed",
  severity_distribution: { critical: 2, high: 6, medium: 18, low: 17, info: 10 },
  duplicate_groups: 8,
  in_scope: ["*.scanme.sh", "scanme.sh"],
  out_of_scope: ["auth.scanme.sh", "admin.*"],
  raw_findings: [
    { id: "f1", tool: "nuclei", target: "scanme.sh:22", vulnerability: "ssh-auth-methods", severity: "info", description: "SSH Auth Methods - Detection", evidence: "publickey, password", reference: "https://nmap.org/nsedoc/scripts/ssh-auth-methods.html" },
    { id: "f2", tool: "nuclei", target: "scanme.sh:443", vulnerability: "deprecated-tls", severity: "medium", description: "Deprecated TLS 1.0 & 1.1 Protocol Supported", evidence: "tls10, tls11", reference: "https://ssl-config.mozilla.org/" },
    { id: "f3", tool: "sslyze", target: "https://scanme.sh", vulnerability: "TLS 1.0 Supported", severity: "medium", description: "The server supports the deprecated TLS 1.0 protocol.", evidence: "TLS 1.0 accepted by scanme.sh:443", reference: "RFC 8996" },
    { id: "f4", tool: "sslyze", target: "https://scanme.sh", vulnerability: "Weak CBC Cipher Suites", severity: "low", description: "The server accepts TLS cipher suites using CBC mode.", evidence: "TLS_RSA_WITH_AES_128_CBC_SHA", reference: "RFC 8996" },
    { id: "f5", tool: "nmap", target: "scanme.sh:80", vulnerability: "http-slowloris-check", severity: "medium", description: "VULNERABLE: Slowloris DOS attack potential detected.", evidence: "Apache 2.4.41 vulnerable state confirmed", reference: "https://nmap.org/nsedoc/scripts/http-slowloris-check.html" },
    { id: "f6", tool: "wapiti", target: "scanme.sh", vulnerability: "Clickjacking Protection Missing", severity: "low", description: "X-Frame-Options or CSP frame-ancestors is not configured.", evidence: "Header absent on /", reference: "https://owasp.org" },
    { id: "f7", tool: "whatweb", target: "scanme.sh", vulnerability: "Web Technology Stack Fingerprint", severity: "info", description: "Identified technologies: Apache/2.4.41, PHP/7.4.3, OpenSSL/1.1.1f", evidence: "Server banner matching", reference: "https://github.com/urbanadventurer/WhatWeb" },
    { id: "f8", tool: "nikto", target: "scanme.sh:80", vulnerability: "Directory Listing / Uploads Indexing", severity: "medium", description: "Directory indexing is enabled on /uploads/ directory.", evidence: "GET /uploads/ -> Index of /uploads", reference: "CWE-548" },
    { id: "f9", tool: "zap", target: "scanme.sh", vulnerability: "Strict-Transport-Security Header Not Set", severity: "low", description: "HSTS header is absent, allowing unencrypted downgrade attacks.", evidence: "GET https://scanme.sh/ -> Missing Strict-Transport-Security", reference: "OWASP A05:2021" },
  ],
  correlated_findings: [
    { correlation_id: "c1", target: "scanme.sh:443", vulnerability: "Deprecated TLS 1.0 / 1.1 Protocols Enabled", severity: "medium", confidence: 95, contributing_tools: ["nuclei", "sslyze"], conflicting_severity: false, description: "Multiple security engines confirmed that deprecated TLS 1.0 and 1.1 cryptographic suites are active.", evidence: ["TLS 1.0 accepted by scanme.sh:443", "tls10, tls11 detected by nuclei"], reference: "RFC 8996", source_finding_ids: ["f2", "f3"] },
    { correlation_id: "c2", target: "scanme.sh", vulnerability: "Missing HSTS and Anti-Clickjacking Defense", severity: "low", confidence: 90, contributing_tools: ["wapiti", "zap"], conflicting_severity: false, description: "Missing Strict-Transport-Security and X-Frame-Options allows potential MITM downgrade and UI redressing.", evidence: ["Header absent on /", "Missing Strict-Transport-Security"], reference: "OWASP Top 10", source_finding_ids: ["f6", "f9"] },
    { correlation_id: "c3", target: "scanme.sh:80", vulnerability: "Slowloris Denial of Service Potential", severity: "medium", confidence: 85, contributing_tools: ["nmap"], conflicting_severity: false, description: "Web server is vulnerable to thread exhaustion under Slowloris incomplete HTTP request streams.", evidence: ["Apache 2.4.41 vulnerable state confirmed"], reference: "CVE-2007-6750", source_finding_ids: ["f5"] },
    { correlation_id: "c4", target: "scanme.sh:80", vulnerability: "Sensitive Directory Indexing Exposed", severity: "medium", confidence: 80, contributing_tools: ["nikto"], conflicting_severity: false, description: "Server directory indexing allows external visitors to inspect internal files in /uploads/.", evidence: ["GET /uploads/ -> Index of /uploads"], reference: "CWE-548", source_finding_ids: ["f8"] },
  ],
};
