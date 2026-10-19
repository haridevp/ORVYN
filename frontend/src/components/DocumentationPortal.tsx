import { useState } from "react";
import {
  Shield,
  GitBranch,
  Server,
  Code2,
  Copy,
  Check,
  ExternalLink,
  BookOpen,
  Cpu,
  CheckCircle2,
  Sparkles,
  Clock,
  FolderGit2,
  Scale,
  Target,
  Play,
  Film,
  Users,
  AlertTriangle,
  TrendingUp,
  Terminal,
  X,
  FileText,
} from "lucide-react";
import type { ScannerProgress } from "../types";
import { RedamonWorkflowGraph } from "./RedamonWorkflowGraph";

interface DocumentationPortalProps {
  isLocalhost?: boolean;
  onSwitchToConsole?: () => void;
}

const DEFAULT_STANDBY_SCANNERS: ScannerProgress[] = [
  { tool: "nmap", status: "queued", findings_count: 0, simulated: false },
  { tool: "whatweb", status: "queued", findings_count: 0, simulated: false },
  { tool: "sslyze", status: "queued", findings_count: 0, simulated: false },
  { tool: "nikto", status: "queued", findings_count: 0, simulated: false },
  { tool: "zap", status: "queued", findings_count: 0, simulated: false },
  { tool: "nuclei", status: "queued", findings_count: 0, simulated: false },
  { tool: "wapiti", status: "queued", findings_count: 0, simulated: false },
];

const SCANNER_MATRIX = [
  {
    name: "Nmap",
    version: "7.93+",
    mode: "Active",
    phase: "Phase 1: Reconnaissance",
    produces: ["Port", "Service", "Technology", "IP"],
    desc: "Host discovery, port scanning, OS fingerprinting, and standard NSE network reconnaissance.",
    timeout: "60.0s",
  },
  {
    name: "WhatWeb",
    version: "0.5.5",
    mode: "Active/Passive",
    phase: "Phase 1: Reconnaissance",
    produces: ["Technology", "Header", "BaseURL"],
    desc: "Next-gen web scanner fingerprinting 1,800+ frameworks, CMS engines, server headers, and web scripts.",
    timeout: "45.0s",
  },
  {
    name: "SSLyze",
    version: "5.2.0",
    mode: "Active",
    phase: "Phase 1: Reconnaissance",
    produces: ["Certificate", "Vulnerability", "Header"],
    desc: "Fast cryptographic TLS/SSL cipher analyzer, certificate chain validation, Heartbleed & Robot detection.",
    timeout: "45.0s",
  },
  {
    name: "Nikto",
    version: "2.5.0",
    mode: "Active",
    phase: "Phase 1: Reconnaissance",
    produces: ["Vulnerability", "Header", "Endpoint"],
    desc: "Comprehensive web server assessment testing for 6,700+ dangerous CGIs, outdated software, and default files.",
    timeout: "60.0s",
  },
  {
    name: "OWASP ZAP",
    version: "2.15.0",
    mode: "Active",
    phase: "Phase 1: Reconnaissance",
    produces: ["Vulnerability", "Parameter", "BaseURL"],
    desc: "Baseline web application spider and active security alert analyzer against OWASP Top 10 vulnerabilities.",
    timeout: "60.0s",
  },
  {
    name: "Nuclei",
    version: "3.3.0",
    mode: "Active",
    phase: "Phase 3: Targeted Scans",
    produces: ["CVE", "Vulnerability", "MitreData", "Capec"],
    desc: "Fast, template-based vulnerability fuzzing targeting 9,000+ known CVEs, misconfigurations, and zero-days.",
    timeout: "65.0s",
  },
  {
    name: "Wapiti",
    version: "3.1.8",
    mode: "Active",
    phase: "Phase 3: Targeted Scans",
    produces: ["Vulnerability", "Parameter", "Secret"],
    desc: "Black-box web vulnerability auditor executing parameter reflection, XSS, SSRF, and file inclusion attacks.",
    timeout: "65.0s",
  },
  {
    name: "SQLMap",
    version: "1.8",
    mode: "Active",
    phase: "Phase 3: Secondary Trigger",
    produces: ["Vulnerability", "Parameter", "Secret"],
    desc: "Autonomous SQL injection detection and database fingerprinting dynamically spawned upon error discovery.",
    timeout: "60.0s",
  },
  {
    name: "FFuf",
    version: "2.1.0",
    mode: "Active",
    phase: "Phase 3: Secondary Trigger",
    produces: ["Endpoint", "Secret", "ExternalDomain"],
    desc: "High-speed web fuzzer for discovering sensitive hidden directories, backup archives, and leaked `.env` files.",
    timeout: "45.0s",
  },
];

const TEMPLATES_LIST = [
  {
    id: "cve-critical-rce",
    name: "Critical CVE & Remote Code Execution",
    badge: "CRITICAL RCE",
    tags: ["cve", "rce", "oast", "kev"],
    desc: "Targets known unauthenticated RCE vulnerabilities and CISA Known Exploited Vulnerabilities (KEV).",
    duration: "~3-5 min",
  },
  {
    id: "api-security-audit",
    name: "REST API & Microservice Exposure",
    badge: "API AUDIT",
    tags: ["api", "graphql", "swagger", "jwt", "exposure"],
    desc: "Audits OpenAPI/Swagger endpoints, JWT misconfigurations, unauthorized BOLA endpoints, and GraphQL introspection.",
    duration: "~4-6 min",
  },
  {
    id: "cloud-perimeter-ssrf",
    name: "Cloud Perimeter & SSRF Audit",
    badge: "CLOUD & SSRF",
    tags: ["ssrf", "cloud", "aws", "gcp", "azure", "metadata"],
    desc: "Probes for Server-Side Request Forgery against cloud metadata endpoints (169.254.169.254) and S3 bucket leaks.",
    duration: "~3-4 min",
  },
  {
    id: "auth-bypass-injection",
    name: "Authentication Bypass & SQLi",
    badge: "INJECTION",
    tags: ["sqli", "auth-bypass", "nosqli", "default-logins"],
    desc: "Automates SQL/NoSQL injection fuzzing and administrative panel authentication bypass testing.",
    duration: "~5-8 min",
  },
];

const SAMPLE_RAG_QUERIES = [
  {
    title: "SQL Injection in User Authentication Query",
    cve: "CVE-2023-38606",
    cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
    owasp: "A03:2021-Injection",
    confidence: "98.4%",
    similarity: "0.912",
    remediation: "Implement parameterized SQL queries with PDO or ORM prepared statements. Never concatenate user input directly into SQL strings.",
  },
  {
    title: "Missing X-Frame-Options & Clickjacking Exposure",
    cve: "N/A (CWE-1021)",
    cwe: "CWE-1021: Improper Restriction of Rendered UI Layers or Frames",
    owasp: "A05:2021-Security Misconfiguration",
    confidence: "94.8%",
    similarity: "0.884",
    remediation: "Configure the 'Content-Security-Policy: frame-ancestors 'self'' header or set 'X-Frame-Options: SAMEORIGIN' across all web server responses.",
  },
  {
    title: "Apache 2.4.49 Path Traversal & Remote File Read",
    cve: "CVE-2021-41773",
    cwe: "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
    owasp: "A01:2021-Broken Access Control",
    confidence: "99.1%",
    similarity: "0.954",
    remediation: "Upgrade Apache HTTP Server to version 2.4.51 or higher. Ensure 'Require all denied' is set on the root filesystem in httpd.conf.",
  },
];

const DEMO_VIDEOS = [
  {
    id: "full-run",
    title: "End-to-End Autonomous 5-Phase Pentest Execution",
    badge: "PRIMARY DEMO",
    duration: "05:20",
    quality: "1080p 60fps",
    desc: "Complete walkthrough from entering target scope to executing Phase 1 (Recon & Ports), Phase 2 (LLM Template Selection), Phase 3 (Nuclei/Wapiti Fuzzing), Phase 4 (ChromaDB RAG Triage), and downloading the consolidated executive report.",
    topics: [
      "Target Scope Setup & Pre-flight Validation",
      "Asynchronous Celery Non-blocking Execution",
      "Live Port Scanning & WhatWeb Fingerprinting",
      "Ollama (Qwen 2.5:7b) Template Reasoning",
      "RAG Knowledge Triage (OWASP & CVE)",
      "Correlated Executive Markdown/PDF Export",
    ],
    videoUrlSlot: "https://youtube.com/watch?v=ORVYN_DEMO_PHASE_1_TO_5",
  },
  {
    id: "circuit-workflow",
    title: "Interactive Redamon Circuit-Bus Pipeline Walkthrough",
    badge: "WORKFLOW CANVAS",
    duration: "03:15",
    quality: "1080p 60fps",
    desc: "Demonstration of the interactive Circuit-Bus canvas inspired by the Redamon recon framework. Clicking nodes highlights signal propagation across the upper entity band, center tool band, and lower artifact band.",
    topics: [
      "Three-Band Circuit-Bus Topology Overview",
      "Real-time Tool Node Status Indicators",
      "Dependency Data Signals & In-Flight Traces",
      "Secondary Dynamic Triggers (SQLMap, FFuf)",
      "Air-gapped Canvas State Synchronization",
    ],
    videoUrlSlot: "https://youtube.com/watch?v=ORVYN_CIRCUIT_BUS_WORKFLOW",
  },
  {
    id: "ai-rag-triage",
    title: "Local LLM Reasoning & ChromaDB Vector RAG Triage",
    badge: "AI & VECTOR RAG",
    duration: "04:10",
    quality: "1080p 60fps",
    desc: "Deep-dive into the AI decision layer: How discovered perimeter technologies prompt the local Qwen 2.5:7b model to select pentest templates, followed by ChromaDB cosine similarity matching against 5,000+ security chunks.",
    topics: [
      "Local Ollama Qwen 2.5:7b Execution",
      "Zero Cloud Leakage Safeguard Protocol",
      "ChromaDB 5,000+ Chunk Vector Embeddings",
      "Cosine Similarity Threshold Validation",
      "Automated Remediation Code Generation",
    ],
    videoUrlSlot: "https://youtube.com/watch?v=ORVYN_LLM_RAG_TRIAGE",
  },
];

const TEAM_MEMBERS = [
  {
    name: "Haridev P",
    github: "haridevp",
    githubUrl: "https://github.com/haridevp",
    initials: "HP",
    accent: "border-cyan-500/40 bg-cyan-950/20 text-cyan-400",
    contributions: [
      "Overall system architecture, non-blocking Celery/FastAPI orchestration",
      "Redamon-inspired Circuit-Bus interactive canvas UI",
      "Multi-scanner Docker containerization & timeout guards",
      "Autonomous 5-phase reconnaissance and triage pipeline design",
    ],
  },
  {
    name: "Reenu LK",
    github: "ReenuLK",
    githubUrl: "https://github.com/ReenuLK",
    initials: "RL",
    accent: "border-purple-500/40 bg-purple-950/20 text-purple-400",
    contributions: [
      "Nmap, SSLyze, and Nikto scanner integration and parsers",
      "CVE data normalization and CVSS v3.1 scoring formulas",
      "Perimeter network reconnaissance algorithms & service mapping",
      "Vulnerability deduplication and severity distribution logic",
    ],
  },
  {
    name: "Shruthilaya A V",
    github: "Shruthilaya",
    githubUrl: "https://github.com/Shruthilaya",
    initials: "SA",
    accent: "border-emerald-500/40 bg-emerald-950/20 text-emerald-400",
    contributions: [
      "ChromaDB vector database indexing of 5,000+ security chunks",
      "OWASP Top 10, NIST CVE, and MITRE CWE embedding pipelines",
      "Ollama local LLM prompt engineering & structured template selection",
      "False positive pruning benchmarks and similarity scoring",
    ],
  },
  {
    name: "vistanoop (Anoop)",
    github: "vistanoop",
    githubUrl: "https://github.com/vistanoop",
    initials: "VA",
    accent: "border-amber-500/40 bg-amber-950/20 text-amber-400",
    contributions: [
      "Nuclei template mapping and secondary tool orchestration",
      "Dynamic triggering of SQLMap and FFuf upon perimeter discovery",
      "Executive report generator & PDF export pipeline",
      "FastAPI REST endpoints and backend schema validation",
    ],
  },
];

export function DocumentationPortal({
  isLocalhost = false,
  onSwitchToConsole,
}: DocumentationPortalProps = {}) {
  const [activeTab, setActiveTab] = useState<string>("problem");
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [activeRagSample, setActiveRagSample] = useState<number>(0);
  const [activeDocTab, setActiveDocTab] = useState<"arch" | "scanners" | "rag" | "api" | "cli" | "deploy">("arch");
  const [selectedDemoVideo, setSelectedDemoVideo] = useState<typeof DEMO_VIDEOS[0] | null>(null);

  const handleCopy = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const navLinks = [
    { id: "problem", label: "Problem Statement" },
    { id: "objectives", label: "Project Objectives" },
    { id: "methodology", label: "Methodology" },
    { id: "demo-videos", label: "Demo Videos" },
    { id: "progress", label: "Project Progress" },
    { id: "documentation", label: "Documentation" },
    { id: "team", label: "Team Details" },
    { id: "repository", label: "GitHub Repo" },
  ];

  return (
    <div className="min-h-screen bg-[#06070c] text-slate-100 font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* 1. TOP STICKY HEADER & COMMAND MATRIX */}
      <header className="sticky top-0 z-50 border-b border-cyan-500/20 bg-[#07080e]/95 backdrop-blur-xl px-4 lg:px-8 py-3">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
          {/* Logo & Identity */}
          <div className="flex items-center gap-3">
            <div className="relative flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.3)]">
              <Cpu size={16} className="animate-pulse" />
              <div className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#10b981]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-extrabold tracking-widest text-white uppercase">
                  ORVYN
                </span>
                <span className="rounded bg-cyan-500/15 border border-cyan-500/30 px-2 py-0.5 text-[9px] font-mono text-cyan-300 font-bold">
                  DOCUMENTATION PORTAL
                </span>
              </div>
              <p className="text-[10px] font-mono text-slate-400 hidden sm:block">
                Offensive Risk & Vulnerability Intelligence Network
              </p>
            </div>
          </div>

          {/* Navigation Items (Desktop) */}
          <nav className="hidden xl:flex items-center gap-1 text-xs font-mono">
            {navLinks.map((link) => (
              <button
                key={link.id}
                onClick={() => {
                  setActiveTab(link.id);
                  document.getElementById(link.id)?.scrollIntoView({ behavior: "smooth" });
                }}
                className={`px-2.5 py-1.5 rounded-lg transition-all cursor-pointer ${
                  activeTab === link.id
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-xs"
                    : "text-slate-400 hover:text-white hover:bg-neutral-900/60"
                }`}
              >
                {link.label}
              </button>
            ))}
          </nav>

          {/* Right Header Badges & Actions */}
          <div className="flex items-center gap-3">
            {isLocalhost && onSwitchToConsole && (
              <button
                type="button"
                onClick={onSwitchToConsole}
                className="flex items-center gap-1.5 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 hover:from-emerald-400 hover:to-cyan-400 px-3 py-1.5 text-xs font-bold text-black font-mono shadow-[0_0_15px_rgba(16,185,129,0.35)] transition-all cursor-pointer"
                title="Switch to Cyber-Deck Pentest Console on Localhost"
              >
                <Terminal size={13} />
                <span>Console (Local)</span>
              </button>
            )}

            <div className="hidden sm:flex items-center gap-1.5 rounded-xl border border-neutral-800 bg-[#0b0d18] px-3 py-1.5 text-xs font-mono text-slate-400">
              <Shield size={12} className="text-cyan-400" />
              <span>Academic Research</span>
            </div>

            <a
              href="https://github.com/haridevp/ORVYN"
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1.5 rounded-xl border border-cyan-500/30 bg-[#0c0e18] hover:bg-[#121524] hover:border-cyan-400/50 px-3.5 py-1.5 text-xs font-mono text-slate-300 hover:text-white transition-all cursor-pointer shadow-sm"
            >
              <FolderGit2 size={13} className="text-cyan-400" />
              <span>GitHub</span>
              <ExternalLink size={11} className="text-slate-500" />
            </a>
          </div>
        </div>
      </header>

      {/* 2. HERO SHOWCASE SECTION */}
      <section className="relative overflow-hidden pt-12 pb-16 lg:pt-20 lg:pb-24 px-4 lg:px-8 border-b border-cyan-500/10">
        <div className="pointer-events-none absolute -top-40 left-1/4 h-96 w-96 rounded-full bg-cyan-500/10 blur-[120px]" />
        <div className="pointer-events-none absolute top-1/3 right-10 h-96 w-96 rounded-full bg-purple-500/10 blur-[140px]" />
        <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,#0f172a15_1px,transparent_1px),linear-gradient(to_bottom,#0f172a15_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]" />

        <div className="max-w-6xl mx-auto relative z-10 text-center space-y-6">
          <div className="inline-flex items-center gap-2 rounded-full bg-cyan-950/60 border border-cyan-500/30 px-4 py-1.5 text-xs font-mono text-cyan-300 shadow-[0_0_15px_rgba(0,240,255,0.2)]">
            <Sparkles size={13} className="text-cyan-400 animate-pulse" />
            <span>FINAL YEAR CAPSTONE RESEARCH & ACADEMIC DOCUMENTATION PORTAL</span>
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-tight">
            ORVYN: Autonomous <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-purple-400">Penetration Testing & Security RAG</span> Intelligence Network
          </h1>

          <p className="text-base sm:text-lg text-slate-300 max-w-3xl mx-auto leading-relaxed">
            Eliminating uncoordinated, noisy vulnerability scans through an orchestrated <strong>5-phase autonomous reconnaissance pipeline</strong>. Powered by local LLM template selection (<strong>Qwen 2.5:7b</strong>), an interactive <strong>Redamon Circuit-Bus Canvas</strong>, and vector RAG triage over <strong>5,000+ authoritative security chunks</strong> in ChromaDB.
          </p>

          {/* Quick Jump Buttons */}
          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            {isLocalhost && onSwitchToConsole && (
              <button
                onClick={onSwitchToConsole}
                className="flex items-center gap-2 rounded-full bg-gradient-to-r from-emerald-400 to-cyan-400 hover:from-emerald-300 hover:to-cyan-300 px-5 py-2.5 text-xs font-bold text-black font-mono transition-all cursor-pointer shadow-[0_0_20px_rgba(16,185,129,0.4)]"
              >
                <Terminal size={14} />
                <span>Launch Cyber-Deck Console</span>
              </button>
            )}

            <button
              onClick={() => document.getElementById("problem")?.scrollIntoView({ behavior: "smooth" })}
              className="flex items-center gap-2 rounded-full border border-rose-500/40 bg-rose-950/30 hover:bg-rose-900/40 px-5 py-2.5 text-xs font-bold text-rose-300 font-mono transition-all cursor-pointer shadow-xs"
            >
              <AlertTriangle size={14} className="text-rose-400" />
              <span>Problem Statement</span>
            </button>

            <button
              onClick={() => document.getElementById("objectives")?.scrollIntoView({ behavior: "smooth" })}
              className="flex items-center gap-2 rounded-full border border-cyan-500/40 bg-cyan-950/30 hover:bg-cyan-900/40 px-5 py-2.5 text-xs font-bold text-cyan-300 font-mono transition-all cursor-pointer shadow-xs"
            >
              <Target size={14} className="text-cyan-400" />
              <span>Project Objectives</span>
            </button>

            <button
              onClick={() => document.getElementById("methodology")?.scrollIntoView({ behavior: "smooth" })}
              className="flex items-center gap-2 rounded-full border border-purple-500/40 bg-purple-950/30 hover:bg-purple-900/40 px-5 py-2.5 text-xs font-bold text-purple-300 font-mono transition-all cursor-pointer shadow-xs"
            >
              <GitBranch size={14} className="text-purple-400" />
              <span>Methodology & Canvas</span>
            </button>

            <button
              onClick={() => document.getElementById("demo-videos")?.scrollIntoView({ behavior: "smooth" })}
              className="flex items-center gap-2 rounded-full bg-gradient-to-r from-amber-500 to-orange-500 hover:from-amber-400 hover:to-orange-400 px-5 py-2.5 text-xs font-bold text-black font-mono transition-all cursor-pointer shadow-[0_0_15px_rgba(245,158,11,0.3)]"
            >
              <Film size={14} className="text-black" />
              <span>Demonstration Videos</span>
            </button>

            <button
              onClick={() => document.getElementById("team")?.scrollIntoView({ behavior: "smooth" })}
              className="flex items-center gap-2 rounded-full border border-neutral-700 bg-neutral-900/80 hover:bg-neutral-800 px-4 py-2.5 text-xs font-medium text-slate-300 font-mono transition-all cursor-pointer"
            >
              <Users size={14} className="text-slate-400" />
              <span>Team Details</span>
            </button>
          </div>

          {/* KPI Dashboard Ribbon */}
          <div className="pt-8 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-left">
            {[
              { label: "Security Engines", val: "9 Tools", sub: "Nmap, Nuclei, ZAP...", color: "text-cyan-400" },
              { label: "Pipeline Phases", val: "5 Phases", sub: "Autonomous Lifecycle", color: "text-purple-400" },
              { label: "RAG Knowledge", val: "5,000+ Chunks", sub: "OWASP, CVE, CWE", color: "text-emerald-400" },
              { label: "AI Templates", val: "30 Templates", sub: "Qwen 2.5:7b Guided", color: "text-amber-400" },
              { label: "Execution Mode", val: "100% Local", sub: "Air-gapped & Docker", color: "text-blue-400" },
              { label: "Timeout Guard", val: "< 60.0s", sub: "Zero Subprocess Hangs", color: "text-rose-400" },
            ].map((kpi, idx) => (
              <div
                key={idx}
                className="rounded-xl border border-neutral-800/80 bg-[#090b14]/80 p-3.5 backdrop-blur-md hover:border-cyan-500/30 transition-all shadow-sm"
              >
                <div className="text-[10px] font-mono text-slate-500 uppercase">{kpi.label}</div>
                <div className={`text-lg font-bold font-mono mt-0.5 ${kpi.color}`}>{kpi.val}</div>
                <div className="text-[10px] text-slate-400 truncate mt-0.5">{kpi.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 3. MAIN CONTENT CONTAINER */}
      <main className="max-w-7xl mx-auto px-4 lg:px-8 py-12 space-y-24">

        {/* SECTION 1: PROBLEM STATEMENT */}
        <section id="problem" className="space-y-6 scroll-mt-20">
          <div className="border-b border-rose-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-rose-400">
              <AlertTriangle size={14} />
              <span>// 01 THE PROBLEM STATEMENT</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              The Critical Bottlenecks in Traditional Penetration Testing
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Modern digital attack surfaces expand continuously, yet security auditing methodologies remain trapped in manual, uncoordinated, and costly operational silos.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              {
                title: "Prohibitive Delays & Costs",
                metric: "2 - 4 Weeks",
                sub: "$15k - $50k / Audit",
                desc: "Manual security assessments require senior penetration testers to conduct tedious reconnaissance. Audits take weeks, leaving production assets exposed during high-velocity release cycles.",
                border: "border-rose-500/30 bg-rose-950/15 text-rose-400",
              },
              {
                title: "Disconnected Tool Silos",
                metric: "0% Cross-Feeding",
                sub: "Zero Intelligence Handoff",
                desc: "Standalone scanners (Nmap, Nikto, Nuclei) run independently without data sharing. Discovered open ports or software versions from one tool do not automatically inform downstream vulnerability probes.",
                border: "border-amber-500/30 bg-amber-950/15 text-amber-400",
              },
              {
                title: "Alert Fatigue & Noise",
                metric: "40% - 60%",
                sub: "False Positive Ratio",
                desc: "Generic scanners generate voluminous reports littered with unverified alerts. Security engineers drown in noise without context-aware triage against authoritative OWASP, NIST, and MITRE benchmarks.",
                border: "border-cyan-500/30 bg-cyan-950/15 text-cyan-400",
              },
              {
                title: "Cloud Privacy & Data Leaks",
                metric: "Sensitive Leaks",
                sub: "Target Exposure Risk",
                desc: "Transmitting internal IP ranges, architecture diagrams, and raw vulnerability traces to external commercial cloud AI APIs creates severe regulatory compliance and intelligence leakage hazards.",
                border: "border-purple-500/30 bg-purple-950/15 text-purple-400",
              },
            ].map((prob, idx) => (
              <div
                key={idx}
                className={`rounded-2xl border ${prob.border} p-5 space-y-3 flex flex-col justify-between backdrop-blur-sm shadow-md hover:scale-[1.01] transition-all`}
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10px] font-bold uppercase tracking-wider opacity-70">
                      BOTTLENECK 0{idx + 1}
                    </span>
                    <span className="rounded px-2 py-0.5 text-[9px] font-mono font-bold uppercase border border-current">
                      {prob.sub}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-2">{prob.title}</h3>
                  <div className="text-2xl font-extrabold font-mono text-white mt-1">{prob.metric}</div>
                  <p className="text-xs text-slate-300 mt-2 leading-relaxed">{prob.desc}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Comparison Table */}
          <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 shadow-xl overflow-x-auto">
            <h3 className="text-sm font-mono font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
              <Scale size={15} className="text-cyan-400" />
              <span>Comparative Analysis: Traditional vs. ORVYN Autonomous Engine</span>
            </h3>
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-neutral-800 text-slate-400">
                  <th className="pb-3 font-semibold">Assessment Dimension</th>
                  <th className="pb-3 font-semibold text-rose-400">Traditional Penetration Testing</th>
                  <th className="pb-3 font-semibold text-cyan-400">ORVYN Autonomous Network</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-900 text-slate-300">
                <tr>
                  <td className="py-2.5 font-bold text-white">Execution Speed</td>
                  <td className="py-2.5 text-rose-300">Days to weeks per engagement</td>
                  <td className="py-2.5 text-cyan-300">Sub-minute phased execution with automated handoffs</td>
                </tr>
                <tr>
                  <td className="py-2.5 font-bold text-white">Tool Coordination</td>
                  <td className="py-2.5 text-rose-300">Manual copy-pasting of outputs between CLI tools</td>
                  <td className="py-2.5 text-cyan-300">Dynamic circuit-bus artifact propagation across 9 tools</td>
                </tr>
                <tr>
                  <td className="py-2.5 font-bold text-white">Targeted Intelligence</td>
                  <td className="py-2.5 text-rose-300">Blind default fuzzing or human intuition</td>
                  <td className="py-2.5 text-cyan-300">Local LLM (Qwen 2.5:7b) technology reasoning</td>
                </tr>
                <tr>
                  <td className="py-2.5 font-bold text-white">False Positive Mitigation</td>
                  <td className="py-2.5 text-rose-300">Manual verification by expensive security analysts</td>
                  <td className="py-2.5 text-cyan-300">ChromaDB Vector RAG triage over 5,000+ security chunks</td>
                </tr>
                <tr>
                  <td className="py-2.5 font-bold text-white">Data Privacy</td>
                  <td className="py-2.5 text-rose-300">Third-party external cloud dependencies</td>
                  <td className="py-2.5 text-cyan-300">100% Air-gapped capable on Docker with zero cloud telemetry</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        {/* SECTION 2: PROJECT OBJECTIVES */}
        <section id="objectives" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <Target size={14} />
              <span>// 02 PROJECT OBJECTIVES</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Strategic Objectives & Measurable Deliverables
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Architecting an open-source, reproducible, and verifiable autonomous framework that transforms vulnerability assessment into a disciplined engineering science.
            </p>
          </div>

          {/* Primary Mission Banner */}
          <div className="rounded-2xl border border-cyan-500/30 bg-gradient-to-r from-cyan-950/40 via-purple-950/30 to-blue-950/20 p-6 shadow-xl space-y-2">
            <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-cyan-400 block">
              PRIMARY ACADEMIC & RESEARCH MISSION
            </span>
            <p className="text-base sm:text-lg font-semibold text-white leading-relaxed">
              &ldquo;To research, engineer, and validate an air-gapped autonomous penetration testing platform that unites multi-scanner orchestration, local LLM-assisted template selection, circuit-bus reconnaissance visualization, and vector-grounded RAG triage into an auditable and zero-hang architecture.&rdquo;
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              {
                num: "01",
                title: "Autonomous 5-Phase Pipeline",
                desc: "Unify reconnaissance, technology fingerprinting, targeted scanning, RAG knowledge triage, and executive reporting into a seamless, deterministic sequential lifecycle.",
                tag: "AUTONOMY",
              },
              {
                num: "02",
                title: "100% Local AI Reasoning",
                desc: "Deploy Ollama Qwen 2.5:7b locally to analyze discovered open ports and server headers, selecting specific pentest templates with strict zero-cloud data leak guarantees.",
                tag: "PRIVACY",
              },
              {
                num: "03",
                title: "Circuit-Bus Recon Graph",
                desc: "Implement an interactive, high-density visualization canvas adhering to Redamon framework specifications with upper entity, center tool, and lower artifact signal bands.",
                tag: "VISUALIZATION",
              },
              {
                num: "04",
                title: "Grounded Security RAG Engine",
                desc: "Embed and index 5,000+ authoritative chunks from OWASP Top 10, NIST CVE, and MITRE CWE/CAPEC in ChromaDB to verify findings and calculate confidence scores.",
                tag: "ACCURACY",
              },
              {
                num: "05",
                title: "Federation of 9 Security Engines",
                desc: "Standardize inputs and outputs across 9 battle-tested security tools (Nmap, WhatWeb, SSLyze, Nikto, ZAP, Nuclei, Wapiti, SQLMap, FFuf) in a unified JSON schema.",
                tag: "ORCHESTRATION",
              },
              {
                num: "06",
                title: "Zero-Hang Subprocess Safety",
                desc: "Enforce strict per-tool timeouts (<60.0s), non-blocking asyncio subprocess wrappers, private network IP guards, and Docker container sandboxing.",
                tag: "RESILIENCE",
              },
            ].map((obj, idx) => (
              <div
                key={idx}
                className="rounded-2xl border border-neutral-800 bg-[#090b14]/90 p-5 space-y-3 hover:border-cyan-500/40 transition-all shadow-sm"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-cyan-400">OBJECTIVE {obj.num}</span>
                  <span className="rounded bg-neutral-900 border border-neutral-800 px-2 py-0.5 text-[9px] font-mono text-slate-400 font-bold">
                    {obj.tag}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white">{obj.title}</h3>
                <p className="text-xs text-slate-300 leading-relaxed">{obj.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* SECTION 3: METHODOLOGY */}
        <section id="methodology" className="space-y-6 scroll-mt-20">
          <div className="border-b border-purple-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-purple-400">
              <GitBranch size={14} />
              <span>// 03 RESEARCH & ARCHITECTURAL METHODOLOGY</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Choreographed 5-Phase Lifecycle & Redamon Circuit-Bus Pipeline
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Rather than firing tools concurrently without context, ORVYN enforces a staged pentest lifecycle where early reconnaissance artifacts inform and trigger specialized downstream engines.
            </p>
          </div>

          {/* 5 Phases Grid */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            {[
              {
                step: "01",
                name: "Initial Scanning",
                badge: "RECON & PORTS",
                tools: "Nmap, WhatWeb, SSLyze, Nikto, ZAP",
                desc: "Perimeter fingerprinting, discovering open ports, SSL/TLS cryptographic strengths, and server banners.",
                color: "border-blue-500/30 bg-blue-950/20 text-blue-400",
              },
              {
                step: "02",
                name: "LLM Template Selection",
                badge: "AI VALIDATION",
                tools: "Ollama (Qwen 2.5:7b)",
                desc: "Evaluates discovered perimeter technologies against 30 pentest templates to select targeted test vectors.",
                color: "border-purple-500/30 bg-purple-950/20 text-purple-400",
              },
              {
                step: "03",
                name: "Targeted Tool Execution",
                badge: "TARGETED FUZZING",
                tools: "Nuclei, Wapiti, SQLMap, FFuf",
                desc: "Runs Nuclei with LLM-selected tags and dynamically spawns secondary engines for parameter & directory testing.",
                color: "border-cyan-500/30 bg-cyan-950/20 text-cyan-400",
              },
              {
                step: "04",
                name: "RAG Knowledge Triage",
                badge: "CHROMA VECTOR DB",
                tools: "ChromaDB (5,000+ chunks)",
                desc: "Matches discovered vulnerabilities against OWASP Top 10, NIST CVEs, and MITRE CWEs to filter false positives.",
                color: "border-emerald-500/30 bg-emerald-950/20 text-emerald-400",
              },
              {
                step: "05",
                name: "Correlated Report",
                badge: "EXECUTIVE REPORT",
                tools: "De-duplication Engine",
                desc: "Synthesizes multi-engine findings into verified executive reports with confidence scores and PDF export.",
                color: "border-amber-500/30 bg-amber-950/20 text-amber-400",
              },
            ].map((phase, idx) => (
              <div
                key={idx}
                className={`rounded-2xl border ${phase.color} p-5 space-y-3 flex flex-col justify-between backdrop-blur-sm shadow-md hover:scale-[1.02] transition-all`}
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold opacity-60">PHASE {phase.step}</span>
                    <span className="rounded px-2 py-0.5 text-[9px] font-mono font-bold uppercase border border-current">
                      {phase.badge}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-2">{phase.name}</h3>
                  <p className="text-xs text-slate-300 mt-2 leading-relaxed">{phase.desc}</p>
                </div>
                <div className="pt-2 border-t border-white/10 text-[11px] font-mono opacity-80">
                  <span className="text-slate-400 block text-[9px] uppercase">Engines:</span>
                  <span className="text-white">{phase.tools}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Three Bands Architecture Explainer */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div className="rounded-xl border border-blue-500/30 bg-blue-950/15 p-4 space-y-1.5">
              <span className="text-blue-400 font-bold uppercase tracking-wider block">▲ Upper Data Band</span>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                Represents initial reconnaissance artifacts: <code>Domain</code>, <code>Subdomain</code>, <code>IP</code>, <code>Port</code>, <code>Service</code>, <code>BaseURL</code>, <code>Endpoint</code>, and <code>CVE</code>.
              </p>
            </div>
            <div className="rounded-xl border border-cyan-500/30 bg-cyan-950/15 p-4 space-y-1.5">
              <span className="text-cyan-400 font-bold uppercase tracking-wider block">⚡ Center Tool Band (9 Stages)</span>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                Sequential tool pipeline: Target Input ➔ Discovery ➔ OSINT ➔ Port Recon ➔ HTTP Probing ➔ Crawling ➔ JS Recon ➔ Vuln Fuzzing ➔ RAG Analysis.
              </p>
            </div>
            <div className="rounded-xl border border-purple-500/30 bg-purple-950/15 p-4 space-y-1.5">
              <span className="text-purple-400 font-bold uppercase tracking-wider block">▼ Lower Data Band</span>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                Enriched secondary intelligence: <code>DNSRecord</code>, <code>Certificate</code>, <code>Header</code>, <code>Technology</code>, <code>Parameter</code>, <code>Secret</code>, <code>MitreData</code>, <code>Capec</code>.
              </p>
            </div>
          </div>

          {/* Embedded Interactive Redamon Workflow Graph */}
          <div className="rounded-2xl border border-cyan-500/30 bg-[#080a14] p-2 shadow-2xl overflow-hidden">
            <div className="px-4 py-2 bg-[#0c0f1e] border-b border-cyan-500/20 flex items-center justify-between text-xs font-mono text-slate-400">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
                <span className="text-white font-semibold">Interactive Circuit-Bus Canvas Live Preview</span>
                <span className="text-slate-500">| Click nodes to highlight dependency signal bus traces</span>
              </div>
              <span className="text-[10px] text-cyan-400">Circuit Bus Graph Engine v3.0</span>
            </div>
            <div className="overflow-x-auto p-2">
              <RedamonWorkflowGraph scanners={DEFAULT_STANDBY_SCANNERS} isRunning={false} />
            </div>
          </div>
        </section>

        {/* SECTION 4: DEMONSTRATION VIDEOS */}
        <section id="demo-videos" className="space-y-6 scroll-mt-20">
          <div className="border-b border-amber-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-amber-400">
              <Film size={14} />
              <span>// 04 DEMONSTRATION VIDEOS</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Recorded Demonstration & Capstone Defense Showcase
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Demonstration videos illustrating autonomous scanning, interactive canvas telemetry, and local RAG knowledge verification. Direct video links are primed in these reserved slots.
            </p>
          </div>

          {/* Notice Callout */}
          <div className="flex items-center gap-3 rounded-xl border border-amber-500/30 bg-amber-950/20 px-4 py-3 text-xs font-mono text-amber-300">
            <Sparkles size={16} className="text-amber-400 shrink-0" />
            <div>
              <span className="font-bold">Demonstration Slots Reserved:</span> Below are the pre-configured video slots for project defense. Video files and live streaming links can be viewed in the interactive viewer modal.
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {DEMO_VIDEOS.map((video) => (
              <div
                key={video.id}
                className="group rounded-2xl border border-neutral-800 bg-[#090b14] overflow-hidden hover:border-amber-500/40 transition-all flex flex-col justify-between shadow-lg"
              >
                {/* Video Screen Placeholder */}
                <div className="relative aspect-video bg-gradient-to-br from-neutral-900 via-[#0d1020] to-neutral-950 border-b border-neutral-800/80 flex items-center justify-center overflow-hidden">
                  {/* Futuristic Grid Lines */}
                  <div className="absolute inset-0 bg-[linear-gradient(to_right,#00f0ff08_1px,transparent_1px),linear-gradient(to_bottom,#00f0ff08_1px,transparent_1px)] bg-[size:1.5rem_1.5rem]" />
                  
                  {/* Top Badges */}
                  <div className="absolute top-3 left-3 flex items-center gap-2">
                    <span className="rounded bg-amber-500/20 border border-amber-500/40 px-2 py-0.5 text-[9px] font-mono font-bold text-amber-300">
                      {video.badge}
                    </span>
                    <span className="rounded bg-black/60 border border-neutral-700 px-1.5 py-0.5 text-[9px] font-mono text-neutral-300">
                      {video.quality}
                    </span>
                  </div>

                  <div className="absolute top-3 right-3 flex items-center gap-1.5 rounded-full bg-black/70 border border-neutral-800 px-2 py-0.5 text-[10px] font-mono text-slate-300">
                    <Clock size={11} className="text-amber-400" />
                    <span>{video.duration}</span>
                  </div>

                  {/* Play Button Trigger */}
                  <button
                    onClick={() => setSelectedDemoVideo(video)}
                    className="relative z-10 flex h-14 w-14 items-center justify-center rounded-full bg-amber-500/20 border-2 border-amber-400 text-amber-300 shadow-[0_0_25px_rgba(245,158,11,0.4)] group-hover:scale-110 group-hover:bg-amber-400 group-hover:text-black transition-all cursor-pointer"
                    title={`Open Demo: ${video.title}`}
                  >
                    <Play size={22} className="ml-0.5 fill-current" />
                  </button>

                  {/* Bottom Video Status Ribbon */}
                  <div className="absolute bottom-2 inset-x-3 flex items-center justify-between text-[10px] font-mono text-slate-400 bg-black/70 rounded px-2 py-1 backdrop-blur-xs">
                    <span className="flex items-center gap-1 text-emerald-400">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                      <span>Slot Reserved</span>
                    </span>
                    <span className="text-slate-500 truncate">ORVYN_DEMO_{video.id.toUpperCase()}</span>
                  </div>
                </div>

                {/* Video Info Content */}
                <div className="p-5 space-y-3 flex-1 flex flex-col justify-between">
                  <div>
                    <h3 className="text-base font-bold text-white group-hover:text-amber-300 transition-colors">
                      {video.title}
                    </h3>
                    <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                      {video.desc}
                    </p>

                    {/* Topic Tags */}
                    <div className="mt-3 space-y-1">
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">
                        Agenda Topics:
                      </span>
                      <ul className="space-y-1">
                        {video.topics.slice(0, 3).map((topic, i) => (
                          <li key={i} className="text-[11px] font-mono text-slate-300 flex items-center gap-1.5">
                            <span className="h-1 w-1 rounded-full bg-amber-400" />
                            <span className="truncate">{topic}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* CTA Button */}
                  <div className="pt-3 border-t border-neutral-800/80 flex items-center gap-2">
                    <button
                      onClick={() => setSelectedDemoVideo(video)}
                      className="flex-1 flex items-center justify-center gap-2 rounded-xl bg-amber-500/15 border border-amber-500/40 hover:bg-amber-500/25 px-3 py-2 text-xs font-mono font-bold text-amber-300 transition-all cursor-pointer"
                    >
                      <Play size={12} className="fill-current" />
                      <span>Watch Demo (Link Slot)</span>
                    </button>
                    <button
                      onClick={() => handleCopy(video.videoUrlSlot, `video-${video.id}`)}
                      className="rounded-xl border border-neutral-800 bg-[#0c0e18] hover:bg-neutral-800 p-2 text-slate-400 hover:text-white transition-all cursor-pointer"
                      title="Copy Demo Link Placeholder"
                    >
                      {copiedCode === `video-${video.id}` ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* SECTION 5: PROJECT PROGRESS & SPRINT MILESTONES */}
        <section id="progress" className="space-y-6 scroll-mt-20">
          <div className="border-b border-emerald-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
              <TrendingUp size={14} />
              <span>// 05 PROJECT PROGRESS & SPRINT MILESTONES</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Development Milestones & Sprint Progress
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Tracking completed iterations, active sprints, and upcoming deliverables leading up to the final academic defense and publication.
            </p>
          </div>

          {/* High-level Progress Metric Bar */}
          <div className="rounded-2xl border border-emerald-500/30 bg-[#090b14] p-5 shadow-xl space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 font-mono text-xs text-white">
                <span className="font-bold uppercase tracking-wider text-emerald-400">Overall Project Completion</span>
                <span className="rounded bg-emerald-500/20 border border-emerald-500/40 px-2 py-0.5 text-[10px] text-emerald-300 font-bold">
                  100% COMPLETED
                </span>
              </div>
              <span className="font-mono text-xs text-slate-400">All 5 Core Engineering Milestones Fully Implemented & Production-Ready</span>
            </div>
            {/* Visual Bar */}
            <div className="h-3 w-full rounded-full bg-neutral-900 overflow-hidden p-0.5 border border-neutral-800">
              <div className="h-full rounded-full bg-gradient-to-r from-cyan-400 via-emerald-400 to-teal-400 transition-all duration-500 shadow-[0_0_15px_rgba(16,185,129,0.5)]" style={{ width: "100%" }} />
            </div>
          </div>

          {/* 5 Milestones Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              {
                phase: "Milestone 1",
                title: "Problem Formulation & Architecture",
                progress: 100,
                status: "Completed",
                badgeColor: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
                deliverables: [
                  "Literature review on Redamon & OWASP standards",
                  "FastAPI + Celery + Redis architecture design",
                  "Unified schema definition for multi-scanner results",
                  "Non-destructive scan scope safeguards",
                ],
              },
              {
                phase: "Milestone 2",
                title: "Multi-Scanner Wrapper Engine",
                progress: 100,
                status: "Completed",
                badgeColor: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
                deliverables: [
                  "Dockerized 9 security engines (Nmap, ZAP, Nuclei...)",
                  "Asyncio subprocess wrappers with strict <60s timeouts",
                  "Structured JSON output normalization",
                  "Simulated fallback generators for CI/CD",
                ],
              },
              {
                phase: "Milestone 3",
                title: "Local LLM & ChromaDB RAG Pipeline",
                progress: 100,
                status: "Completed",
                badgeColor: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
                deliverables: [
                  "Ollama integration with Qwen 2.5:7b local model",
                  "30 Curated pentest templates with tag selectors",
                  "ChromaDB vector database setup with 5,000+ chunks",
                  "Cosine similarity scoring & false positive reduction",
                ],
              },
              {
                phase: "Milestone 4",
                title: "Redamon Circuit-Bus Canvas UI",
                progress: 100,
                status: "Completed",
                badgeColor: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
                deliverables: [
                  "React + TypeScript high-density interactive canvas",
                  "Three-band signal routing (Upper, Center, Lower)",
                  "Dynamic node signal highlight on click",
                  "Real-time scan status log streaming",
                ],
              },
              {
                phase: "Milestone 5",
                title: "Correlated Report Engine",
                progress: 100,
                status: "Completed",
                badgeColor: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
                deliverables: [
                  "Multi-engine vulnerability de-duplication",
                  "CVSS v3.1 calculation & severity distribution",
                  "Executive Markdown & PDF report generation",
                  "Remediation guidance synthesis",
                ],
              },
            ].map((m, idx) => (
              <div
                key={idx}
                className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-3 flex flex-col justify-between hover:border-neutral-700 transition-all shadow-md"
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-slate-400 uppercase">{m.phase}</span>
                    <span className={`rounded px-2 py-0.5 text-[9px] font-mono font-bold uppercase border ${m.badgeColor}`}>
                      {m.status} ({m.progress}%)
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-1">{m.title}</h3>
                  <div className="h-1.5 w-full rounded-full bg-neutral-900 mt-2 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        m.progress === 100 ? "bg-emerald-400" : "bg-cyan-400"
                      }`}
                      style={{ width: `${m.progress}%` }}
                    />
                  </div>
                  <ul className="mt-3 space-y-1.5 font-mono text-[11px] text-slate-300">
                    {m.deliverables.map((item, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <CheckCircle2 size={12} className={m.progress === 100 ? "text-emerald-400 mt-0.5" : "text-cyan-400 mt-0.5"} />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* SECTION 6: COMPREHENSIVE TECHNICAL DOCUMENTATION */}
        <section id="documentation" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <BookOpen size={14} />
              <span>// 06 COMPREHENSIVE TECHNICAL DOCUMENTATION</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Architecture Specifications & Engineering Reference
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Deep technical specifications, non-blocking execution pipelines, toolchain schemas, REST API documentation, and CLI references.
            </p>
          </div>

          {/* Doc Tabs Selector */}
          <div className="flex flex-wrap items-center gap-2 border-b border-neutral-800 pb-2">
            {[
              { id: "arch", label: "System Architecture (RFC-01)" },
              { id: "scanners", label: "Scanner Matrix (9 Tools)" },
              { id: "rag", label: "Security RAG & ChromaDB" },
              { id: "api", label: "REST API Contracts" },
              { id: "cli", label: "CLI Reference" },
              { id: "deploy", label: "Docker Deployment" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveDocTab(tab.id as typeof activeDocTab)}
                className={`rounded-xl px-3.5 py-1.5 text-xs font-mono font-medium transition-all cursor-pointer ${
                  activeDocTab === tab.id
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-xs"
                    : "text-slate-400 hover:text-white hover:bg-neutral-900"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab 1: Architecture */}
          {activeDocTab === "arch" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-3 font-mono text-xs">
                  <h3 className="text-sm font-bold text-white uppercase flex items-center gap-2">
                    <Cpu size={15} className="text-cyan-400" />
                    <span>Non-Blocking Asynchronous Core</span>
                  </h3>
                  <p className="text-slate-300 leading-relaxed text-[11px]">
                    ORVYN decouples HTTP request handling from security tool execution. Every scan request triggers a distributed background job dispatched via Redis message broker and executed by isolated worker processes.
                  </p>
                  <ul className="space-y-1.5 text-slate-300 text-[11px]">
                    <li>• <strong>Framework:</strong> FastAPI (Python 3.11 ASGI)</li>
                    <li>• <strong>Task Queue:</strong> Celery 5.3+ backed by Redis 7</li>
                    <li>• <strong>Process Model:</strong> Asyncio non-blocking subprocess pools</li>
                    <li>• <strong>Timeout Enforcement:</strong> Hard timeout killing via SIGTERM/SIGKILL</li>
                  </ul>
                </div>

                <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-3 font-mono text-xs">
                  <h3 className="text-sm font-bold text-white uppercase flex items-center gap-2">
                    <Shield size={15} className="text-purple-400" />
                    <span>Safety & Scope Enforcement</span>
                  </h3>
                  <p className="text-slate-300 leading-relaxed text-[11px]">
                    To guarantee ethical testing and prevent accidental disruption, ORVYN implements pre-flight validation on all inputs before scanner invocation.
                  </p>
                  <ul className="space-y-1.5 text-slate-300 text-[11px]">
                    <li>• <strong>RFC-1918 Guard:</strong> Blocks private subnets (10.0.0.0/8, 192.168.0.0/16) unless explicitly whitelisted</li>
                    <li>• <strong>Non-Destructive Profiles:</strong> Safe, Passive, Active, and Aggressive profiles</li>
                    <li>• <strong>Rate Limiting:</strong> Nuclei rate-limited to 150 req/sec; Nmap max-rate capped</li>
                    <li>• <strong>Host Validation:</strong> Regex validation for FQDN and IPv4/IPv6 syntax</li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Scanners */}
          {activeDocTab === "scanners" && (
            <div className="rounded-2xl border border-neutral-800 bg-[#090b14] overflow-hidden shadow-xl">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#0c0e18] border-b border-neutral-800 text-slate-400">
                    <tr>
                      <th className="py-3 px-4 font-semibold">Engine</th>
                      <th className="py-3 px-4 font-semibold">Version</th>
                      <th className="py-3 px-4 font-semibold">Execution Phase</th>
                      <th className="py-3 px-4 font-semibold">Artifacts Produced</th>
                      <th className="py-3 px-4 font-semibold">Hard Timeout</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-neutral-900 text-slate-300">
                    {SCANNER_MATRIX.map((s, idx) => (
                      <tr key={idx} className="hover:bg-neutral-900/50">
                        <td className="py-2.5 px-4 font-bold text-white flex items-center gap-2">
                          <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                          <span>{s.name}</span>
                        </td>
                        <td className="py-2.5 px-4 text-slate-400">{s.version}</td>
                        <td className="py-2.5 px-4 text-purple-300">{s.phase}</td>
                        <td className="py-2.5 px-4">
                          <div className="flex flex-wrap gap-1">
                            {s.produces.map((p, i) => (
                              <span key={i} className="rounded bg-neutral-900 border border-neutral-800 px-1.5 py-0.2 text-[10px] text-cyan-300">
                                {p}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="py-2.5 px-4 font-mono text-rose-300">{s.timeout}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Tab 3: RAG Engine */}
          {activeDocTab === "rag" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {SAMPLE_RAG_QUERIES.map((rag, idx) => (
                  <div
                    key={idx}
                    onClick={() => setActiveRagSample(idx)}
                    className={`rounded-2xl border p-4 space-y-2 cursor-pointer transition-all ${
                      activeRagSample === idx
                        ? "border-emerald-500/50 bg-emerald-950/20 text-white shadow-md"
                        : "border-neutral-800 bg-[#090b14] text-slate-400 hover:border-neutral-700"
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] font-mono">
                      <span className="text-emerald-400 font-bold">{rag.cve}</span>
                      <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.2 text-emerald-300">
                        {rag.confidence} Match
                      </span>
                    </div>
                    <h4 className="text-xs font-bold text-white line-clamp-1">{rag.title}</h4>
                    <p className="text-[11px] text-slate-400 line-clamp-2">{rag.remediation}</p>
                  </div>
                ))}
              </div>

              <div className="rounded-2xl border border-emerald-500/30 bg-[#090b14] p-5 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between border-b border-neutral-800 pb-2">
                  <span className="font-bold text-white flex items-center gap-2">
                    <Scale size={14} className="text-emerald-400" />
                    <span>Selected Vector RAG Verified Remediation Trace</span>
                  </span>
                  <span className="text-slate-400 text-[11px]">
                    Cosine Similarity: {SAMPLE_RAG_QUERIES[activeRagSample].similarity}
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
                  <div>
                    <span className="text-slate-500 block">Identified CWE Classification:</span>
                    <span className="text-white font-bold">{SAMPLE_RAG_QUERIES[activeRagSample].cwe}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">OWASP Top 10 Mapping:</span>
                    <span className="text-purple-300 font-bold">{SAMPLE_RAG_QUERIES[activeRagSample].owasp}</span>
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-neutral-950 border border-neutral-800 text-emerald-300 text-[11px] leading-relaxed">
                  <span className="text-slate-500 block text-[9px] uppercase font-bold mb-1">Authoritative Remediation Guidance:</span>
                  {SAMPLE_RAG_QUERIES[activeRagSample].remediation}
                </div>
              </div>

              {/* AI Pentest Templates */}
              <div className="space-y-3 pt-2">
                <span className="text-[11px] font-mono text-purple-400 font-bold uppercase tracking-wider block">
                  AI-Selected Pentest Attack Templates (Ollama Qwen 2.5:7b)
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  {TEMPLATES_LIST.map((tpl) => (
                    <div key={tpl.id} className="rounded-xl border border-neutral-800 bg-neutral-950/80 p-3.5 space-y-2 font-mono text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-white font-bold">{tpl.name}</span>
                        <span className="rounded bg-purple-500/20 border border-purple-500/40 px-1.5 py-0.5 text-[9px] text-purple-300 font-bold">
                          {tpl.badge}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400">{tpl.desc}</p>
                      <div className="flex flex-wrap items-center gap-1 pt-1">
                        {tpl.tags.map((t, idx) => (
                          <span key={idx} className="rounded bg-neutral-900 border border-neutral-800 px-1.5 py-0.2 text-[9px] text-slate-300">
                            #{t}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Tab 4: API Reference */}
          {activeDocTab === "api" && (
            <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-4 font-mono text-xs">
              <h3 className="text-sm font-bold text-white uppercase flex items-center gap-2">
                <Code2 size={15} className="text-cyan-400" />
                <span>REST API OpenAPI Endpoints</span>
              </h3>
              <div className="space-y-2">
                {[
                  { method: "POST", path: "/api/scan/start", desc: "Initiate autonomous scan job with target, scope, and selected scanners." },
                  { method: "GET", path: "/api/scan/{scan_id}/status", desc: "Poll real-time tool state, logs stream, and severity counters." },
                  { method: "GET", path: "/api/scan/{scan_id}/results", desc: "Retrieve verified vulnerability findings, CVSS scores, and evidence." },
                  { method: "POST", path: "/api/scan/{scan_id}/cancel", desc: "Send immediate SIGTERM to kill active subprocesses." },
                  { method: "POST", path: "/api/rag/query", desc: "Execute semantic cosine similarity search across 5,000+ ChromaDB security chunks." },
                  { method: "GET", path: "/api/templates", desc: "List all 30 available AI-guided vulnerability scanning templates." },
                ].map((ep, idx) => (
                  <div key={idx} className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-xl bg-neutral-950 border border-neutral-800/80">
                    <div className="flex items-center gap-2">
                      <span className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                        ep.method === "POST" ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30" : "bg-purple-500/20 text-purple-400 border border-purple-500/30"
                      }`}>
                        {ep.method}
                      </span>
                      <code className="text-white font-bold">{ep.path}</code>
                    </div>
                    <span className="text-slate-400 text-[11px]">{ep.desc}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tab 5: CLI */}
          {activeDocTab === "cli" && (
            <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-4 font-mono text-xs">
              <h3 className="text-sm font-bold text-white uppercase flex items-center gap-2">
                <Terminal size={15} className="text-cyan-400" />
                <span>Terminal CLI Execution Commands</span>
              </h3>
              <div className="space-y-3">
                <div className="relative rounded-xl bg-black/80 border border-neutral-800 p-3">
                  <span className="text-slate-500 text-[10px] block mb-1"># Run Full 5-Phase Autonomous Scan:</span>
                  <pre className="text-cyan-300 overflow-x-auto">python -m src.backend.main --target example.com --profile standard --enable-rag</pre>
                  <button
                    onClick={() => handleCopy("python -m src.backend.main --target example.com --profile standard --enable-rag", "cli-1")}
                    className="absolute top-3 right-3 text-slate-500 hover:text-white"
                  >
                    {copiedCode === "cli-1" ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                  </button>
                </div>

                <div className="relative rounded-xl bg-black/80 border border-neutral-800 p-3">
                  <span className="text-slate-500 text-[10px] block mb-1"># Run Specific Scanner Chain with Template:</span>
                  <pre className="text-purple-300 overflow-x-auto">python -m src.backend.main --target example.com --scanners nmap,whatweb,nuclei --template cve-critical-rce</pre>
                  <button
                    onClick={() => handleCopy("python -m src.backend.main --target example.com --scanners nmap,whatweb,nuclei --template cve-critical-rce", "cli-2")}
                    className="absolute top-3 right-3 text-slate-500 hover:text-white"
                  >
                    {copiedCode === "cli-2" ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Tab 6: Deployment */}
          {activeDocTab === "deploy" && (
            <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-4 font-mono text-xs">
              <h3 className="text-sm font-bold text-white uppercase flex items-center gap-2">
                <Server size={15} className="text-cyan-400" />
                <span>One-Click Docker Compose Deployment</span>
              </h3>
              <div className="relative rounded-xl bg-black/80 border border-neutral-800 p-4">
                <pre className="text-emerald-300 overflow-x-auto leading-relaxed">{`# Clone the repository
git clone https://github.com/haridevp/ORVYN.git
cd ORVYN

# Start the full containerized stack (FastAPI, Redis, Celery, ChromaDB, Frontend)
docker compose up --build -d

# Verify system health
curl http://localhost:8000/health
# {"status": "ok", "scanners": 9, "chromadb": "online", "celery": "ready"}`}</pre>
                <button
                  onClick={() => handleCopy("git clone https://github.com/haridevp/ORVYN.git\ncd ORVYN\ndocker compose up --build -d", "docker-cmd")}
                  className="absolute top-4 right-4 text-slate-500 hover:text-white"
                >
                  {copiedCode === "docker-cmd" ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                </button>
              </div>
            </div>
          )}
        </section>

        {/* SECTION 7: TEAM DETAILS */}
        <section id="team" className="space-y-6 scroll-mt-20">
          <div className="border-b border-purple-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-purple-400">
              <Users size={14} />
              <span>// 07 PROJECT TEAM & RESEARCH CREDITS</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Project Team & Contributors
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Final Year Capstone Research Project &bull; Department of Computer Science & Engineering. Developed collaboratively under agile sprint governance.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {TEAM_MEMBERS.map((member, idx) => (
              <div
                key={idx}
                className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-4 hover:border-cyan-500/40 transition-all flex flex-col justify-between shadow-lg"
              >
                <div>
                  {/* Avatar and Pill */}
                  <div className="flex items-center justify-between">
                    <div className={`h-12 w-12 rounded-xl border flex items-center justify-center font-mono font-extrabold text-base ${member.accent}`}>
                      {member.initials}
                    </div>
                    <span className="rounded bg-neutral-900 border border-neutral-800 px-2.5 py-0.5 text-[10px] font-mono text-slate-400">
                      Team Member
                    </span>
                  </div>

                  {/* Name */}
                  <div className="mt-3">
                    <h3 className="text-lg font-bold text-white">{member.name}</h3>
                  </div>

                  {/* Contributions */}
                  <div className="mt-4 space-y-1.5">
                    <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">
                      Core Contributions:
                    </span>
                    <ul className="space-y-1 text-[11px] font-mono text-slate-300">
                      {member.contributions.map((c, i) => (
                        <li key={i} className="flex items-start gap-1.5">
                          <span className="h-1 w-1 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                          <span>{c}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* GitHub Profile Link */}
                <div className="pt-3 border-t border-neutral-800/80">
                  <a
                    href={member.githubUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center justify-between text-xs font-mono text-slate-400 hover:text-white transition-colors"
                  >
                    <span className="flex items-center gap-1.5">
                      <FolderGit2 size={13} className="text-cyan-400" />
                      <span>@{member.github}</span>
                    </span>
                    <ExternalLink size={12} className="text-slate-500" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* SECTION 8: GITHUB REPOSITORY LINK */}
        <section id="repository" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <FolderGit2 size={14} />
              <span>// 08 OPEN SOURCE REPOSITORY</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              GitHub Repository & Source Code Access
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Access the complete open-source codebase, setup guides, backend microservices, and technical RFC documentation on GitHub.
            </p>
          </div>

          <div className="rounded-2xl border border-cyan-500/30 bg-gradient-to-br from-[#090c18] via-[#070a14] to-[#04060c] p-6 lg:p-8 shadow-2xl space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xl font-extrabold text-white">haridevp/ORVYN</span>
                  <span className="rounded bg-cyan-500/20 border border-cyan-500/40 px-2 py-0.5 text-[10px] font-mono text-cyan-300 font-bold">
                    PUBLIC REPO
                  </span>
                </div>
                <p className="text-xs font-mono text-slate-400">
                  AI-Automated Penetration Testing & Security RAG Intelligence Network
                </p>
              </div>

              <div className="flex items-center gap-3">
                <a
                  href="https://github.com/haridevp/ORVYN"
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-400 to-teal-400 hover:from-cyan-300 hover:to-teal-300 px-5 py-2.5 text-xs font-bold text-black font-mono shadow-[0_0_20px_rgba(0,240,255,0.3)] transition-all cursor-pointer"
                >
                  <FolderGit2 size={15} />
                  <span>Open on GitHub</span>
                  <ExternalLink size={13} />
                </a>
              </div>
            </div>

            {/* Quick Clone Terminal Box */}
            <div className="relative rounded-xl bg-black/90 border border-neutral-800 p-4 font-mono text-xs">
              <div className="flex items-center justify-between text-slate-500 text-[10px] mb-1.5">
                <span>QUICK CLONE REPOSITORY (HTTPS)</span>
                <span>BASH / ZSH</span>
              </div>
              <div className="flex items-center justify-between gap-4">
                <code className="text-cyan-300 font-bold selection:bg-cyan-500/30 selection:text-white">
                  git clone https://github.com/haridevp/ORVYN.git
                </code>
                <button
                  onClick={() => handleCopy("git clone https://github.com/haridevp/ORVYN.git", "repo-clone")}
                  className="flex items-center gap-1.5 rounded-lg border border-neutral-700 bg-neutral-900 hover:bg-neutral-800 px-3 py-1.5 text-xs text-slate-300 hover:text-white transition-all cursor-pointer shrink-0"
                >
                  {copiedCode === "repo-clone" ? (
                    <>
                      <Check size={13} className="text-emerald-400" />
                      <span className="text-emerald-400 font-bold">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy size={13} />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Repository Quick Links Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
              <a
                href="https://github.com/haridevp/ORVYN/blob/main/docs/TECHNICAL_DETAILS.md"
                target="_blank"
                rel="noreferrer"
                className="rounded-xl border border-neutral-800 bg-[#0a0d1c] p-3 hover:border-cyan-500/40 transition-all flex items-center justify-between"
              >
                <span className="flex items-center gap-2 text-slate-300 hover:text-white">
                  <FileText size={14} className="text-cyan-400" />
                  <span>TECHNICAL_DETAILS.md</span>
                </span>
                <ExternalLink size={11} className="text-slate-500" />
              </a>

              <a
                href="https://github.com/haridevp/ORVYN/blob/main/README.md"
                target="_blank"
                rel="noreferrer"
                className="rounded-xl border border-neutral-800 bg-[#0a0d1c] p-3 hover:border-cyan-500/40 transition-all flex items-center justify-between"
              >
                <span className="flex items-center gap-2 text-slate-300 hover:text-white">
                  <BookOpen size={14} className="text-purple-400" />
                  <span>Project README.md</span>
                </span>
                <ExternalLink size={11} className="text-slate-500" />
              </a>

              <a
                href="https://github.com/haridevp/ORVYN/blob/main/docs/BACKLOG.md"
                target="_blank"
                rel="noreferrer"
                className="rounded-xl border border-neutral-800 bg-[#0a0d1c] p-3 hover:border-cyan-500/40 transition-all flex items-center justify-between"
              >
                <span className="flex items-center gap-2 text-slate-300 hover:text-white">
                  <TrendingUp size={14} className="text-emerald-400" />
                  <span>Sprints BACKLOG.md</span>
                </span>
                <ExternalLink size={11} className="text-slate-500" />
              </a>

              <a
                href="https://github.com/haridevp/ORVYN/issues"
                target="_blank"
                rel="noreferrer"
                className="rounded-xl border border-neutral-800 bg-[#0a0d1c] p-3 hover:border-cyan-500/40 transition-all flex items-center justify-between"
              >
                <span className="flex items-center gap-2 text-slate-300 hover:text-white">
                  <AlertTriangle size={14} className="text-amber-400" />
                  <span>Issue Tracker</span>
                </span>
                <ExternalLink size={11} className="text-slate-500" />
              </a>
            </div>
          </div>
        </section>

      </main>

      {/* 4. FOOTER */}
      <footer className="border-t border-neutral-800 bg-[#05060a] px-4 lg:px-8 py-10 mt-20">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6 font-mono text-xs text-slate-400">
          <div className="flex items-center gap-3">
            <Cpu size={16} className="text-cyan-400" />
            <span>
              ORVYN &bull; Academic Research Initiative &bull; Department of Computer Science & Engineering
            </span>
          </div>

          <div className="flex items-center gap-4 text-[11px]">
            <a
              href="https://github.com/haridevp/ORVYN"
              target="_blank"
              rel="noreferrer"
              className="text-cyan-400 hover:text-white transition-colors"
            >
              GitHub Repository
            </a>
            <span>&bull;</span>
            <button
              onClick={() => document.getElementById("documentation")?.scrollIntoView({ behavior: "smooth" })}
              className="hover:text-white transition-colors cursor-pointer"
            >
              Documentation
            </button>
            <span>&bull;</span>
            <button
              onClick={() => document.getElementById("demo-videos")?.scrollIntoView({ behavior: "smooth" })}
              className="hover:text-white transition-colors cursor-pointer"
            >
              Demonstration Videos
            </button>
            <span>&bull;</span>
            <button
              onClick={() => document.getElementById("team")?.scrollIntoView({ behavior: "smooth" })}
              className="hover:text-white transition-colors cursor-pointer"
            >
              Team Details
            </button>
          </div>
        </div>

        <div className="max-w-7xl mx-auto text-center mt-6 pt-6 border-t border-neutral-900 text-[10px] font-mono text-slate-600">
          Disclaimer: ORVYN is designed exclusively for authorized penetration testing, security auditing, and academic research. Unauthorized testing against systems without explicit permission is illegal.
        </div>
      </footer>

      {/* 5. INTERACTIVE DEMO VIDEO VIEWER MODAL */}
      {selectedDemoVideo && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
          <div className="relative w-full max-w-3xl rounded-2xl border border-amber-500/40 bg-[#080a14] p-6 shadow-2xl space-y-4">
            {/* Modal Header */}
            <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
              <div className="flex items-center gap-2">
                <Film size={18} className="text-amber-400" />
                <h3 className="text-base font-bold text-white font-mono">{selectedDemoVideo.title}</h3>
              </div>
              <button
                onClick={() => setSelectedDemoVideo(null)}
                className="rounded-lg p-1 text-slate-400 hover:text-white hover:bg-neutral-800 transition-colors cursor-pointer"
              >
                <X size={18} />
              </button>
            </div>

            {/* Video Player Display Container */}
            <div className="relative aspect-video rounded-xl bg-black border border-neutral-800 flex flex-col items-center justify-center p-6 text-center space-y-3 overflow-hidden">
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(245,158,11,0.1),transparent_70%)]" />
              <div className="relative z-10 flex h-16 w-16 items-center justify-center rounded-full bg-amber-500/20 border-2 border-amber-400 text-amber-400 shadow-[0_0_20px_rgba(245,158,11,0.3)]">
                <Play size={28} className="ml-1 fill-current" />
              </div>
              <div className="relative z-10 space-y-1">
                <span className="rounded bg-amber-500/20 border border-amber-500/40 px-3 py-1 text-xs font-mono font-bold text-amber-300">
                  DEMONSTRATION VIDEO SLOT RESERVED
                </span>
                <p className="text-xs text-slate-400 font-mono max-w-md pt-2">
                  The video embed link for <strong>{selectedDemoVideo.title}</strong> will be connected directly to this player slot upon final upload.
                </p>
              </div>
            </div>

            {/* Video Agenda Details */}
            <div className="rounded-xl border border-neutral-800 bg-[#0d1020] p-4 space-y-2 font-mono text-xs">
              <span className="text-slate-400 font-bold uppercase text-[10px] block">Walkthrough Agenda & Key Topics:</span>
              <ul className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-slate-300 text-[11px]">
                {selectedDemoVideo.topics.map((t, i) => (
                  <li key={i} className="flex items-center gap-1.5">
                    <CheckCircle2 size={12} className="text-amber-400 shrink-0" />
                    <span>{t}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Modal Actions */}
            <div className="flex items-center justify-between pt-2 border-t border-neutral-800 text-xs font-mono">
              <span className="text-slate-500">Duration: {selectedDemoVideo.duration} &bull; Quality: {selectedDemoVideo.quality}</span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCopy(selectedDemoVideo.videoUrlSlot, "modal-copy")}
                  className="flex items-center gap-1.5 rounded-lg border border-neutral-700 bg-neutral-900 hover:bg-neutral-800 px-3 py-1.5 text-slate-300 hover:text-white transition-all cursor-pointer"
                >
                  {copiedCode === "modal-copy" ? (
                    <>
                      <Check size={13} className="text-emerald-400" />
                      <span>Copied Slot URL</span>
                    </>
                  ) : (
                    <>
                      <Copy size={13} />
                      <span>Copy Video Slot Link</span>
                    </>
                  )}
                </button>
                <button
                  onClick={() => setSelectedDemoVideo(null)}
                  className="rounded-lg bg-neutral-800 hover:bg-neutral-700 px-4 py-1.5 text-white transition-all cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
