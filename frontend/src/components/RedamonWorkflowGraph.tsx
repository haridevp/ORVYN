import { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Settings,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Sliders,
  Info,
  Maximize2,
  Minimize2,
} from "lucide-react";
import type { ScannerProgress, ScannerFinding } from "../types";

export interface RedamonWorkflowGraphProps {
  scanners?: ScannerProgress[];
  target?: string;
  isRunning?: boolean;
  onToggleTool?: (toolName: string, enabled: boolean) => void;
  onRunPartialRecon?: (toolName: string) => void;
  liveFindings?: ScannerFinding[];
}

export interface ToolDef {
  id: string;
  name: string;
  stage: string;
  column: number;
  row: number;
  modes: ("ACTIVE" | "PASSIVE")[];
  defaultEnabled: boolean;
  consumes: string[];
  produces: string[];
  enriches: string[];
  description: string;
  stageColor: string; // Tailwind hex or class
  binaryAlias?: string;
}

export interface DataNodeDef {
  id: string;
  name: string;
  category: "identity" | "network" | "web" | "technology" | "security" | "external";
  position: "upper" | "lower";
  colorHex: string;
  borderHex: string;
}

const DATA_NODES: DataNodeDef[] = [
  // Upper Band
  { id: "Domain", name: "Domain", category: "identity", position: "upper", colorHex: "#3b82f6", borderHex: "rgba(59,130,246,0.4)" },
  { id: "Subdomain", name: "Subdomain", category: "identity", position: "upper", colorHex: "#38bdf8", borderHex: "rgba(56,189,248,0.4)" },
  { id: "IP", name: "IP", category: "network", position: "upper", colorHex: "#14b8a6", borderHex: "rgba(20,184,166,0.4)" },
  { id: "Port", name: "Port", category: "network", position: "upper", colorHex: "#06b6d4", borderHex: "rgba(6,182,212,0.4)" },
  { id: "Service", name: "Service", category: "network", position: "upper", colorHex: "#0ea5e9", borderHex: "rgba(14,165,233,0.4)" },
  { id: "BaseURL", name: "BaseURL", category: "web", position: "upper", colorHex: "#10b981", borderHex: "rgba(16,185,129,0.4)" },
  { id: "Endpoint", name: "Endpoint", category: "web", position: "upper", colorHex: "#22c55e", borderHex: "rgba(34,197,94,0.4)" },
  { id: "CVE", name: "CVE", category: "security", position: "upper", colorHex: "#f97316", borderHex: "rgba(249,115,22,0.4)" },

  // Lower Band
  { id: "DNSRecord", name: "DNSRecord", category: "network", position: "lower", colorHex: "#0891b2", borderHex: "rgba(8,145,178,0.4)" },
  { id: "Certificate", name: "Certificate", category: "web", position: "lower", colorHex: "#10b981", borderHex: "rgba(16,185,129,0.4)" },
  { id: "Header", name: "Header", category: "web", position: "lower", colorHex: "#84cc16", borderHex: "rgba(132,204,22,0.4)" },
  { id: "Technology", name: "Technology", category: "technology", position: "lower", colorHex: "#a855f7", borderHex: "rgba(168,85,247,0.4)" },
  { id: "Parameter", name: "Parameter", category: "web", position: "lower", colorHex: "#4ade80", borderHex: "rgba(74,222,128,0.4)" },
  { id: "Secret", name: "Secret", category: "security", position: "lower", colorHex: "#eab308", borderHex: "rgba(234,179,8,0.4)" },
  { id: "ExternalDomain", name: "ExternalDomain", category: "external", position: "lower", colorHex: "#facc15", borderHex: "rgba(250,204,21,0.4)" },
  { id: "Vulnerability", name: "Vulnerability", category: "security", position: "lower", colorHex: "#f43f5e", borderHex: "rgba(244,63,94,0.4)" },
  { id: "MitreData", name: "MitreData", category: "security", position: "lower", colorHex: "#ef4444", borderHex: "rgba(239,68,68,0.4)" },
  { id: "Capec", name: "Capec", category: "security", position: "lower", colorHex: "#dc2626", borderHex: "rgba(220,38,38,0.4)" },
];

const TOOLS_CONFIG: ToolDef[] = [
  // Stage 1: Input
  {
    id: "target_input",
    name: "Target Input",
    stage: "Input",
    column: 1,
    row: 1,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: [],
    produces: ["Domain", "IP", "BaseURL"],
    enriches: [],
    description: "Primary seed domain or network CIDR entered by operator.",
    stageColor: "#64748b",
  },

  // Stage 2: Discovery
  {
    id: "subdomain_discovery",
    name: "Subdomain Discovery",
    stage: "Discovery",
    column: 2,
    row: 1,
    modes: ["ACTIVE", "PASSIVE"],
    defaultEnabled: true,
    consumes: ["Domain"],
    produces: ["Subdomain", "IP", "DNSRecord", "ExternalDomain"],
    enriches: ["Domain"],
    description: "Active & passive subdomain discovery via CRT.sh, Anubis, Hackertarget & DNS bruteforce.",
    stageColor: "#3b82f6",
  },
  {
    id: "urlscan",
    name: "URLScan",
    stage: "Discovery",
    column: 2,
    row: 2,
    modes: ["PASSIVE"],
    defaultEnabled: false,
    consumes: ["Domain"],
    produces: ["Subdomain", "ExternalDomain", "Endpoint", "Parameter"],
    enriches: ["Domain", "IP", "BaseURL"],
    description: "Queries URLScan.io public scans database for historical artifacts.",
    stageColor: "#3b82f6",
  },
  {
    id: "uncover",
    name: "Uncover",
    stage: "Discovery",
    column: 2,
    row: 3,
    modes: ["PASSIVE"],
    defaultEnabled: false,
    consumes: ["Domain"],
    produces: ["IP", "Subdomain", "Port", "Endpoint"],
    enriches: [],
    description: "Queries search engines (Shodan, Censys, FOFA) via ProjectDiscovery API.",
    stageColor: "#3b82f6",
  },

  // Stage 3: OSINT Enrichment
  {
    id: "shodan",
    name: "Shodan",
    stage: "OSINT",
    column: 3,
    row: 1,
    modes: ["PASSIVE"],
    defaultEnabled: false,
    consumes: ["IP"],
    produces: ["Port", "Service", "Subdomain", "ExternalDomain", "DNSRecord", "Vulnerability", "CVE"],
    enriches: ["IP"],
    description: "Passive search of Internet-wide port scans and exposed services.",
    stageColor: "#0284c7",
  },
  {
    id: "osint_enrichment",
    name: "OSINT Enrichment",
    stage: "OSINT",
    column: 3,
    row: 2,
    modes: ["PASSIVE"],
    defaultEnabled: false,
    consumes: ["IP", "Domain"],
    produces: ["Subdomain", "Port", "Service", "ExternalDomain", "Certificate", "Vulnerability", "CVE"],
    enriches: ["IP", "Domain"],
    description: "Multi-feed intelligence enrichment aggregating Netlas, VirusTotal & AlienVault OTX.",
    stageColor: "#0284c7",
  },

  // Stage 4: Port Scanning
  {
    id: "naabu",
    name: "Naabu",
    stage: "Port Scanning",
    column: 4,
    row: 1,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["IP", "Subdomain"],
    produces: ["Port", "Service"],
    enriches: ["IP", "Domain"],
    description: "SYN/CONNECT high-speed port scanner to find open listener sockets.",
    stageColor: "#06b6d4",
  },
  {
    id: "nmap",
    name: "Nmap",
    stage: "Port Scanning",
    column: 4,
    row: 2,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["IP", "Port"],
    produces: ["Technology", "Vulnerability", "CVE"],
    enriches: ["Port", "Service"],
    description: "Network mapper service version detection and default NSE vulnerability scripts.",
    stageColor: "#06b6d4",
    binaryAlias: "nmap",
  },
  {
    id: "masscan",
    name: "Masscan",
    stage: "Port Scanning",
    column: 4,
    row: 3,
    modes: ["ACTIVE"],
    defaultEnabled: false,
    consumes: ["IP"],
    produces: ["Port", "Service"],
    enriches: ["IP"],
    description: "Asynchronous TCP port scanner transmitting SYN packets across ranges.",
    stageColor: "#06b6d4",
  },

  // Stage 5: HTTP Probing & Fingerprinting
  {
    id: "httpx",
    name: "Httpx",
    stage: "HTTP Probing",
    column: 5,
    row: 1,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["Subdomain", "IP", "Port"],
    produces: ["BaseURL", "Certificate", "Technology", "Header"],
    enriches: ["Subdomain", "Domain"],
    description: "Multi-purpose HTTP toolkit to probe live web servers and extract headers.",
    stageColor: "#10b981",
  },
  {
    id: "whatweb",
    name: "WhatWeb",
    stage: "HTTP Probing",
    column: 5,
    row: 2,
    modes: ["ACTIVE", "PASSIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL"],
    produces: ["Technology", "Header"],
    enriches: ["BaseURL"],
    description: "Next generation web scanner identifying CMSs, analytics packages, servers, and JS libraries.",
    stageColor: "#10b981",
    binaryAlias: "whatweb",
  },
  {
    id: "sslyze",
    name: "SSLyze",
    stage: "HTTP Probing",
    column: 5,
    row: 3,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL", "Port"],
    produces: ["Certificate", "Vulnerability"],
    enriches: ["Certificate"],
    description: "Fast SSL/TLS configuration analyzer verifying deprecated ciphers and certificates.",
    stageColor: "#10b981",
    binaryAlias: "sslyze",
  },

  // Stage 6: Resource Enumeration & Crawling
  {
    id: "katana",
    name: "Katana",
    stage: "Resource Enum",
    column: 6,
    row: 1,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL"],
    produces: ["Endpoint", "Parameter", "BaseURL", "ExternalDomain"],
    enriches: [],
    description: "Next-gen crawling and spidering framework parsing DOM, JS, and HTML links.",
    stageColor: "#eab308",
  },
  {
    id: "hakrawler",
    name: "Hakrawler",
    stage: "Resource Enum",
    column: 6,
    row: 2,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL"],
    produces: ["Endpoint", "Parameter", "BaseURL", "ExternalDomain"],
    enriches: [],
    description: "Fast Go web crawler for gathering endpoints and assets from target pages.",
    stageColor: "#eab308",
  },
  {
    id: "jsluice",
    name: "jsluice",
    stage: "Resource Enum",
    column: 6,
    row: 3,
    modes: ["ACTIVE", "PASSIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL", "Endpoint"],
    produces: ["Endpoint", "Parameter", "BaseURL", "Secret", "ExternalDomain"],
    enriches: [],
    description: "Extracts URLs, paths, secrets, and API keys from JavaScript ASTs.",
    stageColor: "#eab308",
  },
  {
    id: "ffuf",
    name: "FFuf",
    stage: "Resource Enum",
    column: 6,
    row: 4,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL", "Endpoint"],
    produces: ["Endpoint", "BaseURL", "ExternalDomain"],
    enriches: [],
    description: "High-speed web fuzzer hunting for hidden directories, .env leaks, and backup files.",
    stageColor: "#eab308",
    binaryAlias: "ffuf",
  },
  {
    id: "gau",
    name: "GAU",
    stage: "Resource Enum",
    column: 6,
    row: 5,
    modes: ["PASSIVE"],
    defaultEnabled: true,
    consumes: ["Domain", "Subdomain"],
    produces: ["Endpoint", "Parameter", "BaseURL", "ExternalDomain"],
    enriches: [],
    description: "Get All URLs from AlienVault, Wayback Machine, and Common Crawl.",
    stageColor: "#eab308",
  },

  // Stage 7: JS Recon & Web Auditing
  {
    id: "js_recon",
    name: "JS Recon",
    stage: "JS Recon",
    column: 7,
    row: 1,
    modes: ["ACTIVE", "PASSIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL", "Endpoint"],
    produces: ["Secret", "Endpoint", "Technology"],
    enriches: ["Secret"],
    description: "Deep static JavaScript analyzer hunting for hardcoded JWTs, API tokens, and AI SDK keys.",
    stageColor: "#f59e0b",
  },
  {
    id: "nikto",
    name: "Nikto",
    stage: "Web Auditing",
    column: 7,
    row: 2,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL"],
    produces: ["Vulnerability", "Technology"],
    enriches: ["BaseURL"],
    description: "Web server assessment scanner for dangerous files, outdated server software, and CGIs.",
    stageColor: "#f59e0b",
    binaryAlias: "nikto",
  },
  {
    id: "wapiti",
    name: "Wapiti",
    stage: "Web Auditing",
    column: 7,
    row: 3,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL", "Endpoint", "Parameter"],
    produces: ["Vulnerability"],
    enriches: [],
    description: "Black-box web application auditor injecting payloads to find XSS, SQLi, and SSRF.",
    stageColor: "#f59e0b",
    binaryAlias: "wapiti",
  },

  // Stage 8: Vulnerability Scanning
  {
    id: "nuclei",
    name: "Nuclei",
    stage: "Vuln Scanning",
    column: 8,
    row: 1,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL", "Endpoint", "Technology", "Domain"],
    produces: ["Vulnerability", "Endpoint", "Parameter", "CVE", "MitreData", "Capec"],
    enriches: [],
    description: "Fast template-based vulnerability scanner with 9,000+ active security checks.",
    stageColor: "#f43f5e",
    binaryAlias: "nuclei",
  },
  {
    id: "zap",
    name: "OWASP ZAP",
    stage: "Vuln Scanning",
    column: 8,
    row: 2,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL", "Endpoint"],
    produces: ["Vulnerability", "Header"],
    enriches: [],
    description: "OWASP Zed Attack Proxy baseline scanner identifying OWASP Top 10 vulnerabilities.",
    stageColor: "#f43f5e",
    binaryAlias: "zap",
  },
  {
    id: "sqlmap",
    name: "SQLMap",
    stage: "Vuln Scanning",
    column: 8,
    row: 3,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL", "Parameter"],
    produces: ["Vulnerability"],
    enriches: [],
    description: "Automatic SQL injection parameter exploitation and database takeover tool.",
    stageColor: "#f43f5e",
    binaryAlias: "sqlmap",
  },
  {
    id: "security_checks",
    name: "Security Checks",
    stage: "Vuln Scanning",
    column: 8,
    row: 4,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["BaseURL", "IP", "Subdomain", "Domain"],
    produces: ["Vulnerability"],
    enriches: ["IP"],
    description: "26 autonomous security checks analyzing security headers, TLS posture, and DNSSEC.",
    stageColor: "#f43f5e",
  },

  // Stage 9: Enrichment & AI / RAG Validation
  {
    id: "cve_lookup",
    name: "CVE Lookup",
    stage: "Analysis & AI",
    column: 9,
    row: 1,
    modes: ["PASSIVE"],
    defaultEnabled: true,
    consumes: ["Technology"],
    produces: ["CVE", "MitreData", "Capec"],
    enriches: [],
    description: "Resolves discovered service versions against NVD and GitHub Security Advisory DB.",
    stageColor: "#a855f7",
  },
  {
    id: "mitre",
    name: "MITRE ATT&CK",
    stage: "Analysis & AI",
    column: 9,
    row: 2,
    modes: ["PASSIVE"],
    defaultEnabled: true,
    consumes: ["CVE"],
    produces: ["MitreData", "Capec"],
    enriches: [],
    description: "Enriches verified vulnerabilities with MITRE ATT&CK enterprise tactics and CAPEC IDs.",
    stageColor: "#a855f7",
  },
  {
    id: "rag_judge",
    name: "RAG AI Judge",
    stage: "Analysis & AI",
    column: 9,
    row: 3,
    modes: ["ACTIVE"],
    defaultEnabled: true,
    consumes: ["Vulnerability", "CVE", "Technology"],
    produces: ["Vulnerability", "MitreData"],
    enriches: ["Vulnerability"],
    description: "ChromaDB vector RAG validation verifying PoCs against authoritative standards.",
    stageColor: "#a855f7",
  },
];

export function RedamonWorkflowGraph({
  scanners = [],
  target = "target.local",
  isRunning = false,
  onToggleTool,
  onRunPartialRecon,
  liveFindings = [],
}: RedamonWorkflowGraphProps) {
  // Store enabled state for each tool
  const [toolEnabledState, setToolEnabledState] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    TOOLS_CONFIG.forEach((t) => {
      // Check if backend scanners list has this tool
      if (t.binaryAlias) {
        const found = scanners.find((s) => s.tool === t.binaryAlias);
        initial[t.id] = found ? true : t.defaultEnabled;
      } else {
        initial[t.id] = t.defaultEnabled;
      }
    });
    return initial;
  });

  // Selected node for click-highlighting (tool or data node)
  const [selectedNode, setSelectedNode] = useState<{ type: "tool" | "data"; id: string } | null>(null);

  // Settings modal state
  const [activeSettingsTool, setActiveSettingsTool] = useState<ToolDef | null>(null);

  // Filter / view mode
  const [isExpanded, setIsExpanded] = useState<boolean>(false);

  // Toggle a tool
  const handleToggle = (toolId: string) => {
    const nextVal = !toolEnabledState[toolId];
    setToolEnabledState((prev) => ({
      ...prev,
      [toolId]: nextVal,
    }));
    if (onToggleTool) {
      const toolDef = TOOLS_CONFIG.find((t) => t.id === toolId);
      onToggleTool(toolDef?.binaryAlias || toolId, nextVal);
    }
  };

  // Determine starved data nodes (chain-breaking logic)
  const starvedDataNodes = useMemo(() => {
    const activeProducers: Record<string, string[]> = {};
    DATA_NODES.forEach((dn) => {
      activeProducers[dn.id] = [];
    });

    TOOLS_CONFIG.forEach((tool) => {
      if (toolEnabledState[tool.id]) {
        tool.produces.forEach((p) => {
          if (activeProducers[p]) {
            activeProducers[p].push(tool.id);
          }
        });
      }
    });

    const starved = new Set<string>();
    DATA_NODES.forEach((dn) => {
      if (dn.id !== "Domain" && (!activeProducers[dn.id] || activeProducers[dn.id].length === 0)) {
        starved.add(dn.id);
      }
    });
    return starved;
  }, [toolEnabledState]);

  // Determine tools with missing inputs (warning state)
  const toolWarningMap = useMemo(() => {
    const warnings: Record<string, string> = {};
    TOOLS_CONFIG.forEach((tool) => {
      if (toolEnabledState[tool.id]) {
        const missing = tool.consumes.filter((c) => starvedDataNodes.has(c));
        if (missing.length > 0) {
          warnings[tool.id] = `${tool.name} requires ${missing.join(", ")} data, but no active tool is producing it.`;
        }
      }
    });
    return warnings;
  }, [toolEnabledState, starvedDataNodes]);

  // Map backend scanner progress to tools
  const toolProgressMap = useMemo(() => {
    const map: Record<string, ScannerProgress> = {};
    scanners.forEach((s) => {
      const toolConfig = TOOLS_CONFIG.find((t) => t.binaryAlias === s.tool);
      if (toolConfig) {
        map[toolConfig.id] = s;
      }
    });
    return map;
  }, [scanners]);

  // Helper to test if an element is highlighted based on selection
  const isNodeHighlighted = (type: "tool" | "data", id: string) => {
    if (!selectedNode) return true; // everything normal if nothing selected
    if (selectedNode.type === "tool") {
      if (type === "tool") return selectedNode.id === id;
      const tool = TOOLS_CONFIG.find((t) => t.id === selectedNode.id);
      if (!tool) return false;
      return tool.consumes.includes(id) || tool.produces.includes(id) || tool.enriches.includes(id);
    } else {
      if (type === "data") return selectedNode.id === id;
      const tool = TOOLS_CONFIG.find((t) => t.id === id);
      if (!tool) return false;
      return (
        tool.consumes.includes(selectedNode.id) ||
        tool.produces.includes(selectedNode.id) ||
        tool.enriches.includes(selectedNode.id)
      );
    }
  };

  // Group tools by column
  const toolsByColumn = useMemo(() => {
    const cols: Record<number, ToolDef[]> = {};
    for (let i = 1; i <= 9; i++) cols[i] = [];
    TOOLS_CONFIG.forEach((t) => {
      if (cols[t.column]) cols[t.column].push(t);
    });
    return cols;
  }, []);

  const stageTitles: Record<number, string> = {
    1: "Input",
    2: "Discovery",
    3: "OSINT",
    4: "Port Scanning",
    5: "HTTP Probing",
    6: "Resource Enum",
    7: "JS Recon & Audit",
    8: "Vuln Scanning",
    9: "Analysis & AI",
  };

  return (
    <div className={`relative rounded-2xl border border-cyan-500/20 bg-[#090b12] text-slate-200 overflow-hidden shadow-2xl transition-all duration-300 ${isExpanded ? "fixed inset-4 z-50 overflow-auto" : ""}`}>
      {/* Circuit Board / Blueprint Background Mesh */}
      <div
        className="pointer-events-none absolute inset-0 opacity-15"
        style={{
          backgroundImage: `
            radial-gradient(circle at 1px 1px, rgba(0, 240, 255, 0.4) 1px, transparent 0),
            linear-gradient(to right, rgba(255, 255, 255, 0.03) 1px, transparent 1px),
            linear-gradient(to bottom, rgba(255, 255, 255, 0.03) 1px, transparent 1px)
          `,
          backgroundSize: "28px 28px, 56px 56px, 56px 56px",
        }}
      />

      {/* Top Header Bar */}
      <div className="relative z-10 flex flex-wrap items-center justify-between gap-3 border-b border-cyan-500/15 bg-[#0b0e18]/90 px-4 py-3 backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-950/70 border border-cyan-500/30 text-cyan-400 shadow-[0_0_12px_rgba(0,240,255,0.2)]">
            <Sliders size={14} className="text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-bold tracking-wider text-white uppercase font-mono">
                Recon & Pentest Pipeline Workflow
              </h3>
              <span className="rounded-full bg-cyan-500/20 border border-cyan-500/40 px-2 py-0.2 text-[9px] font-mono font-bold text-cyan-300">
                REDAMON INTERACTIVE
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-sans flex items-center gap-2">
              <span>Target: <strong className="text-cyan-300 font-mono">{target}</strong></span>
              <span>•</span>
              <span>Status: <strong className={isRunning ? "text-cyan-400 font-mono animate-pulse" : "text-slate-300 font-mono"}>{isRunning ? "SCANNING ACTIVE" : "READY"}</strong></span>
              {liveFindings && liveFindings.length > 0 && (
                <>
                  <span>•</span>
                  <span>Findings: <strong className="text-rose-400 font-mono">{liveFindings.length}</strong></span>
                </>
              )}
            </p>
          </div>
        </div>

        {/* Header Controls & Stats */}
        <div className="flex items-center gap-2">
          {/* Quick presets */}
          <div className="hidden sm:flex items-center gap-1 rounded-lg bg-[#0f1220] p-1 border border-cyan-500/20 text-[10px] font-mono">
            <button
              onClick={() => {
                const updated: Record<string, boolean> = {};
                TOOLS_CONFIG.forEach((t) => (updated[t.id] = true));
                setToolEnabledState(updated);
              }}
              className="px-2 py-0.5 rounded text-slate-300 hover:text-cyan-300 hover:bg-cyan-950/40 transition-colors cursor-pointer"
            >
              All ON
            </button>
            <button
              onClick={() => {
                const updated: Record<string, boolean> = {};
                TOOLS_CONFIG.forEach((t) => {
                  updated[t.id] = ["target_input", "subdomain_discovery", "httpx", "whatweb", "katana", "nuclei"].includes(t.id);
                });
                setToolEnabledState(updated);
              }}
              className="px-2 py-0.5 rounded text-slate-300 hover:text-cyan-300 hover:bg-cyan-950/40 transition-colors cursor-pointer"
            >
              Fast Recon
            </button>
            <button
              onClick={() => {
                const updated: Record<string, boolean> = {};
                TOOLS_CONFIG.forEach((t) => (updated[t.id] = t.defaultEnabled));
                setToolEnabledState(updated);
              }}
              className="px-2 py-0.5 rounded text-slate-300 hover:text-cyan-300 hover:bg-cyan-950/40 transition-colors cursor-pointer"
            >
              <RotateCcw size={10} className="inline mr-1" />
              Reset
            </button>
          </div>

          {/* Fullscreen Toggle */}
          <button
            onClick={() => setIsExpanded((prev) => !prev)}
            title={isExpanded ? "Collapse View" : "Expand to Fullscreen"}
            className="p-1.5 rounded-lg border border-cyan-500/20 bg-[#0f1220] text-slate-400 hover:text-cyan-300 hover:border-cyan-500/40 transition-colors cursor-pointer"
          >
            {isExpanded ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
          </button>
        </div>
      </div>

      {/* Main Canvas Area */}
      <div className="relative z-10 p-4 overflow-x-auto min-h-[580px] select-none [scrollbar-width:thin]">
        {/* UPPER DATA BAND (Pills) */}
        <div className="mb-4">
          <div className="flex items-center gap-2 mb-2 text-[10px] font-mono text-cyan-400/80 uppercase tracking-widest">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
            <span>Upper Data Bus // Produced & Consumed Entities</span>
          </div>
          <div className="flex flex-wrap items-center gap-2 px-1">
            {DATA_NODES.filter((d) => d.position === "upper").map((dataNode) => {
              const isStarved = starvedDataNodes.has(dataNode.id);
              const isSelected = selectedNode?.type === "data" && selectedNode?.id === dataNode.id;
              const isDimmed = !isNodeHighlighted("data", dataNode.id);

              return (
                <button
                  key={dataNode.id}
                  onClick={() =>
                    setSelectedNode(isSelected ? null : { type: "data", id: dataNode.id })
                  }
                  className={`group relative flex items-center gap-1.5 rounded-full px-3 py-1 text-[11px] font-mono font-medium transition-all duration-200 cursor-pointer border ${
                    isDimmed ? "opacity-30" : "opacity-100"
                  } ${
                    isStarved
                      ? "bg-rose-950/60 border-rose-500/80 text-rose-300 animate-pulse shadow-[0_0_10px_rgba(244,63,94,0.3)]"
                      : isSelected
                      ? "bg-cyan-950/80 border-cyan-400 text-white shadow-[0_0_15px_rgba(0,240,255,0.4)] ring-1 ring-cyan-400"
                      : "bg-[#0d101a] border-slate-800 hover:border-slate-600 text-slate-300 hover:text-white"
                  }`}
                  style={{
                    borderLeftColor: isStarved ? "#f43f5e" : dataNode.colorHex,
                    borderLeftWidth: "3px",
                  }}
                  title={
                    isStarved
                      ? `${dataNode.name} is starved: no active tool is producing it!`
                      : `Click to highlight tools producing & consuming ${dataNode.name}`
                  }
                >
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{ backgroundColor: isStarved ? "#f43f5e" : dataNode.colorHex }}
                  />
                  <span>{dataNode.name}</span>
                  {isStarved && (
                    <AlertTriangle size={11} className="text-rose-400 animate-bounce ml-0.5" />
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* SVG CIRCUIT BUS WIRE TRACES (Background overlay) */}
        <div className="relative my-2">
          {/* TOOL BAND (Center - Grid of Pipeline Columns) */}
          <div className="grid grid-cols-9 gap-3 min-w-[1400px]">
            {([1, 2, 3, 4, 5, 6, 7, 8, 9] as const).map((colNum) => {
              const toolsInCol = toolsByColumn[colNum] || [];

              return (
                <div key={colNum} className="flex flex-col space-y-2.5">
                  {/* Stage Header */}
                  <div className="border-b border-cyan-500/15 pb-1 text-center">
                    <span className="font-mono text-[9px] font-bold uppercase tracking-wider text-cyan-400/90 truncate block">
                      {stageTitles[colNum]}
                    </span>
                  </div>

                  {/* Tool Cards */}
                  <div className="space-y-2.5">
                    {toolsInCol.map((tool) => {
                      const isEnabled = !!toolEnabledState[tool.id];
                      const warning = toolWarningMap[tool.id];
                      const isSelected = selectedNode?.type === "tool" && selectedNode?.id === tool.id;
                      const isDimmed = !isNodeHighlighted("tool", tool.id);
                      const progress = toolProgressMap[tool.id];

                      // Live state badge
                      let liveBadge = null;
                      if (progress) {
                        if (progress.status === "running") {
                          liveBadge = (
                            <span className="flex items-center gap-1 rounded bg-cyan-500/20 border border-cyan-500/40 px-1.5 py-0.2 text-[8px] font-mono text-cyan-300 font-bold">
                              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />
                              RUNNING
                            </span>
                          );
                        } else if (progress.status === "completed") {
                          liveBadge = (
                            <span className="flex items-center gap-1 rounded bg-emerald-500/20 border border-emerald-500/40 px-1.5 py-0.2 text-[8px] font-mono text-emerald-300 font-semibold">
                              <CheckCircle2 size={9} />
                              {progress.findings_count ?? 0} found
                            </span>
                          );
                        } else if (progress.status === "error") {
                          liveBadge = (
                            <span className="flex items-center gap-1 rounded bg-rose-500/20 border border-rose-500/40 px-1.5 py-0.2 text-[8px] font-mono text-rose-300 font-semibold">
                              <XCircle size={9} />
                              ERROR
                            </span>
                          );
                        }
                      }

                      return (
                        <div
                          key={tool.id}
                          onClick={() =>
                            setSelectedNode(isSelected ? null : { type: "tool", id: tool.id })
                          }
                          className={`relative rounded-xl border p-2.5 transition-all duration-200 cursor-pointer ${
                            isDimmed ? "opacity-30" : "opacity-100"
                          } ${
                            !isEnabled
                              ? "bg-[#0b0c12]/60 border-dashed border-neutral-800 text-neutral-500"
                              : isSelected
                              ? "bg-[#111624] border-cyan-400 shadow-[0_0_20px_rgba(0,240,255,0.25)] ring-1 ring-cyan-400"
                              : "bg-[#0f121d] border-neutral-800/90 hover:border-cyan-500/40 hover:bg-[#121626]"
                          }`}
                          style={{
                            borderLeftWidth: "3px",
                            borderLeftColor: isEnabled ? tool.stageColor : "#334155",
                          }}
                        >
                          {/* Top Row: Tool Name + Warning + Settings + Toggle Switch */}
                          <div className="flex items-center justify-between gap-1.5 mb-1.5">
                            <div className="flex items-center gap-1 min-w-0">
                              <span
                                className={`font-bold text-xs truncate tracking-wide ${
                                  isEnabled ? "text-white" : "text-neutral-500"
                                }`}
                              >
                                {tool.name}
                              </span>
                            </div>

                            <div className="flex items-center gap-1 shrink-0" onClick={(e) => e.stopPropagation()}>
                              {/* Amber Warning Indicator (Matching Katana screenshot) */}
                              {warning && (
                                <button
                                  type="button"
                                  title={warning}
                                  className="text-amber-400 hover:text-amber-300 transition-colors animate-pulse"
                                >
                                  <AlertTriangle size={13} />
                                </button>
                              )}

                              {/* Settings Gear Icon */}
                              <button
                                type="button"
                                onClick={() => setActiveSettingsTool(tool)}
                                title={`Configure ${tool.name} parameters`}
                                className="text-slate-500 hover:text-slate-200 transition-colors p-0.5 rounded hover:bg-neutral-800"
                              >
                                <Settings size={12} />
                              </button>

                              {/* Green iOS-Style Interactive Toggle Switch (Matching screenshot) */}
                              {tool.id !== "target_input" && (
                                <button
                                  type="button"
                                  onClick={() => handleToggle(tool.id)}
                                  className={`relative inline-flex h-4 w-7 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                                    isEnabled ? "bg-emerald-500" : "bg-neutral-700"
                                  }`}
                                  title={isEnabled ? `Disable ${tool.name}` : `Enable ${tool.name}`}
                                >
                                  <span
                                    className={`pointer-events-none inline-block h-3 w-3 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                                      isEnabled ? "translate-x-3" : "translate-x-0"
                                    }`}
                                  />
                                </button>
                              )}
                            </div>
                          </div>

                          {/* Middle Row: Active / Passive badges + Live Execution Status */}
                          <div className="flex items-center justify-between gap-1 mt-1">
                            <div className="flex items-center gap-1">
                              {tool.modes.map((mode) => (
                                <span
                                  key={mode}
                                  className={`px-1.5 py-0.2 rounded text-[8px] font-mono font-bold tracking-wider ${
                                    !isEnabled
                                      ? "bg-neutral-900 text-neutral-600"
                                      : mode === "ACTIVE"
                                      ? "bg-rose-950/40 text-rose-400 border border-rose-500/20"
                                      : "bg-emerald-950/40 text-emerald-400 border border-emerald-500/20"
                                  }`}
                                >
                                  {mode}
                                </span>
                              ))}
                            </div>

                            {liveBadge}
                          </div>

                          {/* Partial Recon Launcher (Run this single tool independently) */}
                          {tool.binaryAlias && isEnabled && (
                            <div className="mt-2 pt-1 border-t border-neutral-800/60 flex items-center justify-between text-[9px] font-mono text-slate-400">
                              <span className="truncate text-slate-500">Standalone</span>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  if (onRunPartialRecon) onRunPartialRecon(tool.binaryAlias!);
                                }}
                                className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-cyan-950/40 hover:bg-cyan-900/60 text-cyan-300 border border-cyan-500/30 transition-colors cursor-pointer"
                                title={`Run partial recon for ${tool.name}`}
                              >
                                <Play size={8} />
                                <span>Run</span>
                              </button>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* LOWER DATA BAND (Pills) */}
        <div className="mt-6 pt-3 border-t border-cyan-500/10">
          <div className="flex items-center gap-2 mb-2 text-[10px] font-mono text-cyan-400/80 uppercase tracking-widest">
            <span className="h-1.5 w-1.5 rounded-full bg-purple-400" />
            <span>Lower Data Bus // Enriched & Security Entities</span>
          </div>
          <div className="flex flex-wrap items-center gap-2 px-1">
            {DATA_NODES.filter((d) => d.position === "lower").map((dataNode) => {
              const isStarved = starvedDataNodes.has(dataNode.id);
              const isSelected = selectedNode?.type === "data" && selectedNode?.id === dataNode.id;
              const isDimmed = !isNodeHighlighted("data", dataNode.id);

              return (
                <button
                  key={dataNode.id}
                  onClick={() =>
                    setSelectedNode(isSelected ? null : { type: "data", id: dataNode.id })
                  }
                  className={`group relative flex items-center gap-1.5 rounded-full px-3 py-1 text-[11px] font-mono font-medium transition-all duration-200 cursor-pointer border ${
                    isDimmed ? "opacity-30" : "opacity-100"
                  } ${
                    isStarved
                      ? "bg-rose-950/60 border-rose-500/80 text-rose-300 animate-pulse shadow-[0_0_10px_rgba(244,63,94,0.3)]"
                      : isSelected
                      ? "bg-purple-950/80 border-purple-400 text-white shadow-[0_0_15px_rgba(168,85,247,0.4)] ring-1 ring-purple-400"
                      : "bg-[#0d101a] border-slate-800 hover:border-slate-600 text-slate-300 hover:text-white"
                  }`}
                  style={{
                    borderLeftColor: isStarved ? "#f43f5e" : dataNode.colorHex,
                    borderLeftWidth: "3px",
                  }}
                  title={
                    isStarved
                      ? `${dataNode.name} is starved: no active tool is producing it!`
                      : `Click to highlight tools producing & consuming ${dataNode.name}`
                  }
                >
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{ backgroundColor: isStarved ? "#f43f5e" : dataNode.colorHex }}
                  />
                  <span>{dataNode.name}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Informational Footer Strip with Active Selected Details */}
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl bg-[#0b0d16] p-2.5 border border-cyan-500/15 text-xs font-mono">
          <div className="flex items-center gap-2 text-slate-300">
            <Info size={13} className="text-cyan-400" />
            {selectedNode ? (
              <span>
                Selected: <strong className="text-cyan-300">{selectedNode.id}</strong> (
                {selectedNode.type === "tool" ? "Scanner Module" : "Data Entity"}) • Click again to clear focus
              </span>
            ) : (
              <span>Click any tool card or data entity to highlight its inputs, outputs & dependencies.</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-[10px] text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              <span>Enabled</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-neutral-600" />
              <span>Disabled</span>
            </span>
            <span className="flex items-center gap-1.5">
              <AlertTriangle size={11} className="text-amber-400" />
              <span>Chain Warning</span>
            </span>
          </div>
        </div>
      </div>

      {/* Tool Settings Configuration Modal */}
      <AnimatePresence>
        {activeSettingsTool && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="w-full max-w-lg rounded-2xl border border-cyan-500/30 bg-[#0c0f1a] p-5 shadow-2xl text-slate-200 space-y-4"
            >
              <div className="flex items-center justify-between border-b border-cyan-500/20 pb-3">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-500/30 text-cyan-400">
                    <Settings size={16} />
                  </div>
                  <div>
                    <h3 className="font-bold text-white text-sm tracking-wide">
                      {activeSettingsTool.name} Configuration
                    </h3>
                    <span className="text-[10px] font-mono text-cyan-400">
                      Stage: {activeSettingsTool.stage}
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => setActiveSettingsTool(null)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-neutral-800"
                >
                  <XCircle size={18} />
                </button>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">
                {activeSettingsTool.description}
              </p>

              {/* Data Dependencies Breakdown */}
              <div className="space-y-2 rounded-xl bg-[#090b14] p-3 border border-neutral-800/80 text-xs font-mono">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Consumes (Inputs):</span>
                  <div className="flex flex-wrap gap-1">
                    {activeSettingsTool.consumes.length > 0 ? (
                      activeSettingsTool.consumes.map((c) => (
                        <span key={c} className="px-1.5 py-0.2 rounded bg-cyan-950/60 text-cyan-300 text-[10px]">
                          {c}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-500 text-[10px]">None (Origin Source)</span>
                    )}
                  </div>
                </div>
                <div className="flex items-center justify-between border-t border-neutral-800/60 pt-2">
                  <span className="text-slate-400">Produces (Outputs):</span>
                  <div className="flex flex-wrap gap-1">
                    {activeSettingsTool.produces.map((p) => (
                      <span key={p} className="px-1.5 py-0.2 rounded bg-emerald-950/60 text-emerald-300 text-[10px]">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Quick Parameters */}
              <div className="space-y-3 pt-1">
                <div>
                  <label className="block text-[11px] font-mono text-slate-400 mb-1">
                    Execution Timeout (seconds)
                  </label>
                  <input
                    type="number"
                    defaultValue={45}
                    className="w-full rounded-lg bg-neutral-900 border border-neutral-700 px-3 py-1.5 text-xs text-white focus:border-cyan-400 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-mono text-slate-400 mb-1">
                    Concurrency Rate Limit
                  </label>
                  <input
                    type="number"
                    defaultValue={25}
                    className="w-full rounded-lg bg-neutral-900 border border-neutral-700 px-3 py-1.5 text-xs text-white focus:border-cyan-400 focus:outline-none"
                  />
                </div>
              </div>

              {/* Modal Actions */}
              <div className="flex items-center justify-end gap-2 border-t border-cyan-500/20 pt-3">
                <button
                  type="button"
                  onClick={() => setActiveSettingsTool(null)}
                  className="px-3 py-1.5 rounded-lg border border-neutral-700 text-xs text-slate-300 hover:bg-neutral-800 cursor-pointer"
                >
                  Close
                </button>
                <button
                  type="button"
                  onClick={() => setActiveSettingsTool(null)}
                  className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-black font-semibold text-xs transition-colors cursor-pointer shadow-lg shadow-cyan-500/20"
                >
                  Save Settings
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
