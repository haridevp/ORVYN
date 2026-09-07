export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScannerName = "nuclei" | "zap" | "nikto";
export type ScannerRunState = "queued" | "running" | "completed" | "error";
export type OverallStatus = "queued" | "running" | "completed" | "error";

export interface ScannerFinding {
  id: string;
  tool: ScannerName;
  target: string;
  vulnerability: string;
  severity: Severity;
  description: string;
  evidence?: string | null;
  reference?: string | null;
}

export interface ScannerProgress {
  tool: ScannerName;
  status: ScannerRunState;
  started_at?: string | null;
  finished_at?: string | null;
  findings_count: number;
  error?: string | null;
  simulated: boolean;
}

export interface ScanStatusResponse {
  scan_id: string;
  target: string;
  profile: string;
  overall_status: OverallStatus;
  scanners: ScannerProgress[];
  logs?: string[];
  created_at: string;
  updated_at: string;
}

export interface CorrelatedFinding {
  correlation_id: string;
  target: string;
  vulnerability: string;
  severity: Severity;
  confidence: number;
  contributing_tools: ScannerName[];
  conflicting_severity: boolean;
  description: string;
  evidence: string[];
  reference?: string | null;
  source_finding_ids: string[];
}

export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanResultsResponse {
  scan_id: string;
  target: string;
  overall_status: string;
  raw_findings: ScannerFinding[];
  correlated_findings: CorrelatedFinding[];
  severity_distribution: SeverityDistribution;
  duplicate_groups: number;
  logs?: string[];
}

export interface TargetProbeResponse {
  target: string;
  is_alive: boolean;
  hostname: string;
  ip?: string | null;
  status_code?: number | null;
  latency_ms?: number | null;
  server?: string | null;
  scheme?: string | null;
  error?: string | null;
}
