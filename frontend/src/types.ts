export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScannerName = "nuclei" | "zap" | "nikto" | "whatweb" | "nmap" | "sslyze" | "wapiti" | "sqlmap" | "ffuf";
export type ScannerRunState = "queued" | "running" | "completed" | "error" | "cancelled";
export type OverallStatus = "queued" | "running" | "completed" | "error" | "cancelled";

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

export interface ToolChainStep {
  tool: ScannerName;
  order: number;
  purpose: string;
  flags?: string[];
  nuclei_tags?: string[];
}

export interface ScanTemplate {
  id: string;
  name: string;
  category: string;
  badge: string;
  description: string;
  profile: string;
  scanners: ScannerName[];
  tool_chain: ToolChainStep[];
  nuclei_tags?: string[];
  target_type?: string;
  estimated_duration_sec: number;
  vulnerability_focus: string[];
  is_default?: boolean;
}

export interface EnvironmentInfo {
  os_id: string;
  os_name: string;
  is_kali: boolean;
  is_parrot: boolean;
  is_docker: boolean;
  docker_available: boolean;
  execution_mode: "native_kali" | "native_parrot" | "native_linux" | "dockerized_mcp" | "simulated";
  available_tools: string[];
  missing_tools: string[];
  description: string;
}

export interface LLMDecision {
  selected_template_id: string;
  template_name: string;
  confidence: number;
  reasoning: string;
  recommended_nuclei_tags?: string[];
  recommended_tools?: string[];
  is_llm_decided?: boolean;
  model_name?: string;
}

export interface RAGKnowledgeMatch {
  vulnerability: string;
  verdict: string;
  validated_severity: string;
  confidence: number;
  cve_citations?: string[];
  cwe_citations?: string[];
  owasp_citations?: string[];
  reasoning?: string;
}

export interface RAGComparisonSummary {
  total_validated: number;
  confirmed_count: number;
  suspected_count: number;
  informational_count: number;
  citations_count: number;
  knowledge_base_matches?: RAGKnowledgeMatch[];
}

export interface ScanStatusResponse {
  scan_id: string;
  target: string;
  profile: string;
  template_id?: string | null;
  template_name?: string | null;
  overall_status: OverallStatus;
  current_phase?: "initial_scanning" | "llm_template_selection" | "targeted_tool_execution" | "rag_triage" | "completed" | string | null;
  llm_decision?: LLMDecision | null;
  rag_comparison_summary?: RAGComparisonSummary | null;
  progress_pct: number;
  eta_seconds?: number | null;
  elapsed_seconds: number;
  scanners: ScannerProgress[];
  live_findings?: ScannerFinding[];
  findings_count?: number;
  correlated_count?: number;
  duplicate_groups?: number;
  severity_distribution?: SeverityDistribution;
  in_scope?: string[];
  out_of_scope?: string[];
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
  ai_threat_explanation?: string | null;
  ai_remediation?: string | null;
  ai_validated_severity?: string | null;
  ai_confidence?: number | null;
  ai_status?: "pending" | "completed" | "unavailable" | "error" | null;
  ai_verdict?: "CONFIRMED_VULNERABILITY" | "CONFIRMED" | "SUSPECTED_VULNERABILITY" | "SUSPECTED" | "FALSE_POSITIVE" | "INFORMATIONAL_FINDING" | "INFORMATIONAL" | string | null;
  ai_judge_reasoning?: string | null;
  ai_cve_citations?: string[];
  ai_cwe_citations?: string[];
  ai_owasp_citations?: string[];
  ai_references?: string[];
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
  profile?: string;
  template_id?: string | null;
  template_name?: string | null;
  overall_status: string;
  current_phase?: string | null;
  llm_decision?: LLMDecision | null;
  rag_comparison_summary?: RAGComparisonSummary | null;
  raw_findings: ScannerFinding[];
  correlated_findings: CorrelatedFinding[];
  severity_distribution: SeverityDistribution;
  duplicate_groups: number;
  in_scope?: string[];
  out_of_scope?: string[];
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
