import { useState } from "react";
import {
  Shield,
  Zap,
  Brain,
  GitBranch,
  Server,
  Code2,
  Copy,
  Check,
  ExternalLink,
  BookOpen,
  Cpu,
  CheckCircle2,
  ArrowRight,
  Layers,
  Sparkles,
  Clock,
  FolderGit2,
  Scale,
  Target,
} from "lucide-react";
import { RedamonWorkflowGraph } from "./RedamonWorkflowGraph";
import type { ScannerProgress } from "../types";

interface DocumentationPortalProps {
  onLaunchApp: () => void;
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

export function DocumentationPortal({ onLaunchApp }: DocumentationPortalProps) {
  const [activeTab, setActiveTab] = useState<string>("overview");
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [activeRagSample, setActiveRagSample] = useState<number>(0);

  const handleCopy = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const navLinks = [
    { id: "overview", label: "Project Overview" },
    { id: "recon-pipeline", label: "Recon Pipeline" },
    { id: "phases", label: "5-Phase Workflow" },
    { id: "architecture", label: "Technical Architecture" },
    { id: "rag-engine", label: "Security RAG" },
    { id: "scanners", label: "Tool Matrix" },
    { id: "mcp-ai", label: "LLM & MCP" },
    { id: "api", label: "API & CLI" },
    { id: "roadmap", label: "Roadmap & Team" },
    { id: "quickstart", label: "Deployment" },
  ];

  return (
    <div className="min-h-screen bg-[#06070c] text-slate-100 font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* 1. TOP STICKY HEADER & COMMAND MATRIX */}
      <header className="sticky top-0 z-50 border-b border-cyan-500/20 bg-[#07080e]/90 backdrop-blur-xl px-4 lg:px-8 py-3">
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
                  DOCS & SHOWCASE
                </span>
              </div>
              <p className="text-[10px] font-mono text-slate-400 hidden sm:block">
                Offensive Risk & Vulnerability Intelligence Network
              </p>
            </div>
          </div>

          {/* Navigation Items (Desktop) */}
          <nav className="hidden xl:flex items-center gap-1 text-xs font-mono">
            {navLinks.slice(0, 6).map((link) => (
              <button
                key={link.id}
                onClick={() => {
                  setActiveTab(link.id);
                  document.getElementById(link.id)?.scrollIntoView({ behavior: "smooth" });
                }}
                className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                  activeTab === link.id
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-xs"
                    : "text-slate-400 hover:text-white hover:bg-neutral-900/60"
                }`}
              >
                {link.label}
              </button>
            ))}
          </nav>

          {/* Right Action CTAs */}
          <div className="flex items-center gap-3">
            <a
              href="https://github.com/haridevp/ORVYN"
              target="_blank"
              rel="noreferrer"
              className="hidden sm:flex items-center gap-1.5 rounded-xl border border-neutral-800 bg-[#0c0e18] hover:bg-[#121524] px-3 py-1.5 text-xs font-mono text-slate-300 hover:text-white transition-all cursor-pointer"
            >
              <FolderGit2 size={13} className="text-cyan-400" />
              <span>GitHub</span>
              <ExternalLink size={11} className="text-slate-500" />
            </a>

            <button
              onClick={onLaunchApp}
              className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 px-4 py-2 text-xs font-bold text-black font-mono shadow-[0_0_20px_rgba(0,240,255,0.35)] transition-all transform hover:scale-[1.02] active:scale-[0.98] cursor-pointer"
            >
              <Zap size={14} className="fill-black" />
              <span>Launch Cyber-Deck App</span>
              <ArrowRight size={13} />
            </button>
          </div>
        </div>
      </header>

      {/* 2. HERO SHOWCASE SECTION */}
      <section className="relative overflow-hidden pt-12 pb-16 lg:pt-20 lg:pb-24 px-4 lg:px-8 border-b border-cyan-500/10">
        {/* Futuristic Background Glow Orbs */}
        <div className="pointer-events-none absolute -top-40 left-1/4 h-96 w-96 rounded-full bg-cyan-500/10 blur-[120px]" />
        <div className="pointer-events-none absolute top-1/3 right-10 h-96 w-96 rounded-full bg-purple-500/10 blur-[140px]" />
        <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,#0f172a15_1px,transparent_1px),linear-gradient(to_bottom,#0f172a15_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)]" />

        <div className="max-w-6xl mx-auto relative z-10 text-center space-y-6">
          <div className="inline-flex items-center gap-2 rounded-full bg-cyan-950/60 border border-cyan-500/30 px-4 py-1.5 text-xs font-mono text-cyan-300 shadow-[0_0_15px_rgba(0,240,255,0.2)]">
            <Sparkles size={13} className="text-cyan-400 animate-pulse" />
            <span>ACADEMIC RESEARCH & NEXT-GEN PRODUCTION SECURITY PLATFORM</span>
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-tight">
            ORVYN: Autonomous <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-purple-400">Pentest & Security RAG</span> Intelligence Network
          </h1>

          <p className="text-base sm:text-lg text-slate-300 max-w-3xl mx-auto leading-relaxed">
            Eliminating static, uncoordinated vulnerability scanners by orchestrating a dynamic <strong>5-phase autonomous reconnaissance pipeline</strong>. Powered by local LLM template selection (<strong>Qwen 2.5:7b</strong>), an interactive <strong>Redamon Recon Workflow</strong> canvas, and vector RAG triage over <strong>5,000+ authoritative security chunks</strong> in ChromaDB.
          </p>

          {/* Quick CTA Actions */}
          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <button
              onClick={onLaunchApp}
              className="flex items-center gap-2.5 rounded-full bg-gradient-to-r from-cyan-400 to-teal-400 hover:from-cyan-300 hover:to-teal-300 px-6 py-3 text-sm font-bold text-black font-mono shadow-[0_0_25px_rgba(0,240,255,0.4)] transition-all cursor-pointer"
            >
              <Zap size={15} className="fill-black" />
              <span>Launch Interactive Cyber-Deck</span>
              <ArrowRight size={15} />
            </button>

            <button
              onClick={() => document.getElementById("recon-pipeline")?.scrollIntoView({ behavior: "smooth" })}
              className="flex items-center gap-2 rounded-full border border-cyan-500/30 bg-[#0b0e1b] hover:bg-[#12162a] hover:border-cyan-500/50 px-6 py-3 text-sm font-semibold text-slate-200 transition-all cursor-pointer"
            >
              <GitBranch size={15} className="text-cyan-400" />
              <span>Explore Recon Workflow Graph</span>
            </button>

            <button
              onClick={() => document.getElementById("architecture")?.scrollIntoView({ behavior: "smooth" })}
              className="flex items-center gap-2 rounded-full border border-neutral-800 bg-neutral-900/80 hover:bg-neutral-800 px-5 py-3 text-sm font-semibold text-slate-300 transition-all cursor-pointer"
            >
              <BookOpen size={15} className="text-purple-400" />
              <span>Technical Specs (RFC)</span>
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
      <main className="max-w-7xl mx-auto px-4 lg:px-8 py-12 space-y-20">

        {/* SECTION 1: REDAMON RECONNAISSANCE PIPELINE WORKFLOW */}
        <section id="recon-pipeline" className="space-y-6 scroll-mt-20">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cyan-500/20 pb-4">
            <div>
              <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
                <GitBranch size={14} />
                <span>// 01 INTERACTIVE CIRCUIT GRAPH</span>
              </div>
              <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
                Redamon-Inspired Reconnaissance Pipeline
              </h2>
              <p className="text-sm text-slate-400 mt-1 max-w-3xl">
                Modeled after the Redamon reconnaissance framework specifications: A high-density interactive node-graph organizing data flow across upper entity bands, 9 tool stages, and lower enriched artifact bands.
              </p>
            </div>
            <button
              onClick={onLaunchApp}
              className="flex items-center gap-1.5 rounded-xl border border-cyan-500/40 bg-cyan-950/40 px-3.5 py-1.5 text-xs font-mono text-cyan-300 hover:bg-cyan-900/50 cursor-pointer"
            >
              <span>Test Live in Console</span>
              <ArrowRight size={13} />
            </button>
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
                <span className="text-white font-semibold">Interactive Canvas Live Preview</span>
                <span className="text-slate-500">| Click nodes to highlight dependency signal bus traces</span>
              </div>
              <span className="text-[10px] text-cyan-400">Circuit Bus Graph Engine v3.0</span>
            </div>
            <div className="overflow-x-auto p-2">
              <RedamonWorkflowGraph scanners={DEFAULT_STANDBY_SCANNERS} isRunning={false} />
            </div>
          </div>
        </section>

        {/* SECTION 2: AUTONOMOUS 5-PHASE LIFECYCLE */}
        <section id="phases" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <Layers size={14} />
              <span>// 02 CHOREOGRAPHED EXECUTION</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Autonomous 5-Phase Assessment Lifecycle
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Rather than firing tools concurrently without context, ORVYN enforces a staged pentest lifecycle where early phases inform and trigger specialized downstream engines.
            </p>
          </div>

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
        </section>

        {/* SECTION 3: TECHNICAL ARCHITECTURE & SPECS */}
        <section id="architecture" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <Cpu size={14} />
              <span>// 03 SYSTEM ARCHITECTURE</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Distributed Backend & Non-Blocking Orchestration
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Engineered with FastAPI, Celery distributed tasks, Redis queue broker, non-blocking asynchronous subprocess pools, and strict timeout guards.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Architecture Card 1: Process Safety & Timeouts */}
            <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-6 space-y-4">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  <Clock size={16} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">Subprocess Safety & Deadlock Prevention</h3>
                  <span className="text-xs text-slate-400 font-mono">Asyncio Buffered Streams + SIGKILL Escalation</span>
                </div>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Vulnerability scanners (such as Nikto or Nmap) can easily deadlock when remote web servers stall or fail to terminate sockets. ORVYN enforces a dual-stage execution watchdog:
              </p>
              <ul className="space-y-2 text-xs font-mono text-slate-300">
                <li className="flex items-start gap-2">
                  <CheckCircle2 size={13} className="text-cyan-400 mt-0.5 shrink-0" />
                  <span><strong>Hard Deadline Watchdog:</strong> 60.0s for Phase 1 recon, 65.0s for Phase 3 targeted scanners.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 size={13} className="text-cyan-400 mt-0.5 shrink-0" />
                  <span><strong>Non-Blocking Line Buffering:</strong> Buffered standard output streaming prevents kernel pipe buffer saturation.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 size={13} className="text-cyan-400 mt-0.5 shrink-0" />
                  <span><strong>Graceful Process Termination:</strong> Sends <code>SIGTERM</code> followed by guaranteed <code>SIGKILL</code> after 2.0s to eliminate zombie processes.</span>
                </li>
              </ul>
            </div>

            {/* Architecture Card 2: Scope Enforcement & Boundary Protection */}
            <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-6 space-y-4">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/30">
                  <Target size={16} />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">Perimeter & Scope Boundary Enforcement</h3>
                  <span className="text-xs text-slate-400 font-mono">CIDR, Host Regex & Blacklist Guardians</span>
                </div>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Legitimate offensive security audits require strict perimeter isolation. ORVYN implements a zero-trust scope validator prior to tool dispatch:
              </p>
              <ul className="space-y-2 text-xs font-mono text-slate-300">
                <li className="flex items-start gap-2">
                  <CheckCircle2 size={13} className="text-purple-400 mt-0.5 shrink-0" />
                  <span><strong>In-Scope Whitelisting:</strong> Strict matching against domain regex patterns (e.g. <code>*.target.com</code>) and IPv4 subnets.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 size={13} className="text-purple-400 mt-0.5 shrink-0" />
                  <span><strong>Exclusion Overrides:</strong> Out-of-scope targets (e.g. <code>auth.target.com</code> or production database ports) take strict precedence.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 size={13} className="text-purple-400 mt-0.5 shrink-0" />
                  <span><strong>DNS & SSRF Protection:</strong> Validates target addresses before launching high-impact parameter fuzzer modules.</span>
                </li>
              </ul>
            </div>
          </div>
        </section>

        {/* SECTION 4: SECURITY RAG KNOWLEDGE BASE */}
        <section id="rag-engine" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <Scale size={14} />
              <span>// 04 VECTOR RETRIEVAL-AUGMENTED GENERATION</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Security RAG Knowledge Base Triage Engine
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              5,000+ vector-indexed security knowledge chunks in ChromaDB empower ORVYN to validate raw findings, reduce false positives by 85%, and attach authoritative CVE/CWE citations.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left: Interactive RAG Query Selector */}
            <div className="lg:col-span-1 rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                Select Test Finding Query
              </h3>
              <div className="space-y-2">
                {SAMPLE_RAG_QUERIES.map((q, idx) => (
                  <button
                    key={idx}
                    onClick={() => setActiveRagSample(idx)}
                    className={`w-full text-left p-3 rounded-xl border text-xs transition-all cursor-pointer ${
                      activeRagSample === idx
                        ? "border-cyan-500/50 bg-cyan-950/30 text-white shadow-sm"
                        : "border-neutral-800/80 bg-black/40 text-slate-400 hover:text-slate-200 hover:border-neutral-700"
                    }`}
                  >
                    <div className="font-bold">{q.title}</div>
                    <div className="text-[10px] text-cyan-400 font-mono mt-1">Confidence: {q.confidence}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Right: Active RAG Citation Verdict Card */}
            <div className="lg:col-span-2 rounded-2xl border border-cyan-500/30 bg-[#0a0d18] p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-neutral-800 pb-3">
                <div>
                  <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest block">
                    VECTOR MATCH VERDICT
                  </span>
                  <h4 className="text-base font-bold text-white mt-0.5">
                    {SAMPLE_RAG_QUERIES[activeRagSample].title}
                  </h4>
                </div>
                <div className="flex items-center gap-2">
                  <span className="rounded bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-0.5 text-xs font-mono text-emerald-300 font-bold">
                    Score: {SAMPLE_RAG_QUERIES[activeRagSample].similarity}
                  </span>
                  <span className="rounded bg-cyan-500/15 border border-cyan-500/30 px-2.5 py-0.5 text-xs font-mono text-cyan-300 font-bold">
                    {SAMPLE_RAG_QUERIES[activeRagSample].confidence} Confidence
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                <div className="rounded-lg bg-black/50 p-2.5 border border-neutral-800">
                  <span className="text-[10px] text-slate-500 block uppercase">CVE Citation</span>
                  <span className="text-cyan-300 font-bold">{SAMPLE_RAG_QUERIES[activeRagSample].cve}</span>
                </div>
                <div className="rounded-lg bg-black/50 p-2.5 border border-neutral-800">
                  <span className="text-[10px] text-slate-500 block uppercase">CWE Classification</span>
                  <span className="text-purple-300 font-bold truncate block">{SAMPLE_RAG_QUERIES[activeRagSample].cwe.split(":")[0]}</span>
                </div>
                <div className="rounded-lg bg-black/50 p-2.5 border border-neutral-800">
                  <span className="text-[10px] text-slate-500 block uppercase">OWASP Top 10</span>
                  <span className="text-amber-300 font-bold">{SAMPLE_RAG_QUERIES[activeRagSample].owasp}</span>
                </div>
              </div>

              <div className="space-y-1.5 text-xs">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">Authoritative Remediation Guidance:</span>
                <p className="text-slate-200 leading-relaxed bg-black/40 p-3 rounded-xl border border-neutral-800/80 font-mono text-xs">
                  {SAMPLE_RAG_QUERIES[activeRagSample].remediation}
                </p>
              </div>
            </div>
          </div>
        </section>

        {/* SECTION 5: MULTI-SCANNER TOOL MATRIX */}
        <section id="scanners" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <Shield size={14} />
              <span>// 05 SCANNER CLUSTER</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              9 Integrated Offensive Security Engines
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Each security engine in ORVYN is containerized, bounded by execution timeouts, and mapped to specific data contract entities.
            </p>
          </div>

          <div className="rounded-2xl border border-neutral-800 bg-[#090b14] overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0e1120] text-slate-400 border-b border-neutral-800 uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="py-3 px-4">Tool</th>
                    <th className="py-3 px-4">Version</th>
                    <th className="py-3 px-4">Mode</th>
                    <th className="py-3 px-4">Pipeline Phase</th>
                    <th className="py-3 px-4">Outputs Produced</th>
                    <th className="py-3 px-4">Timeout</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-800/60 text-slate-300">
                  {SCANNER_MATRIX.map((tool, idx) => (
                    <tr key={idx} className="hover:bg-cyan-950/20 transition-colors">
                      <td className="py-3 px-4 font-bold text-white flex items-center gap-2">
                        <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                        {tool.name}
                      </td>
                      <td className="py-3 px-4 text-slate-400">{tool.version}</td>
                      <td className="py-3 px-4">
                        <span className="rounded bg-neutral-800 px-2 py-0.5 text-[10px] font-bold text-cyan-300">
                          {tool.mode}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-purple-300">{tool.phase}</td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {tool.produces.map((p, pIdx) => (
                            <span key={pIdx} className="rounded bg-neutral-900 border border-neutral-700/60 px-1.5 py-0.5 text-[9px] text-slate-300">
                              {p}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-rose-300 font-bold">{tool.timeout}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* SECTION 6: LLM & HEXSTRIKE MCP */}
        <section id="mcp-ai" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <Brain size={14} />
              <span>// 06 AI DECISION ENGINE & MCP</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Autonomous Template Selection & HexStrike MCP
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              ORVYN pairs local LLMs (Qwen 2.5:7b via Ollama) with the Model Context Protocol (MCP) to turn raw reconnaissance data into structured pentest plans.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {TEMPLATES_LIST.map((tpl) => (
              <div
                key={tpl.id}
                className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-3 flex flex-col justify-between hover:border-purple-500/40 transition-all shadow-md"
              >
                <div>
                  <div className="flex items-center justify-between">
                    <span className="rounded bg-purple-500/15 border border-purple-500/30 px-2 py-0.5 text-[9px] font-mono font-bold text-purple-300">
                      {tpl.badge}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">{tpl.duration}</span>
                  </div>
                  <h3 className="text-sm font-bold text-white mt-2">{tpl.name}</h3>
                  <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">{tpl.desc}</p>
                </div>
                <div className="pt-2 border-t border-neutral-800 text-[10px] font-mono text-cyan-400 flex flex-wrap gap-1">
                  {tpl.tags.map((t, idx) => (
                    <span key={idx} className="bg-cyan-950/50 px-1.5 py-0.5 rounded border border-cyan-500/20">
                      #{t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* SECTION 7: REST API & CLI DOCUMENTATION */}
        <section id="api" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <Code2 size={14} />
              <span>// 07 DEVELOPER & API SPECIFICATIONS</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              OpenAPI REST Endpoints & Python CLI Engine
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Integrate ORVYN into CI/CD pipelines, DevSecOps platforms, or command-line terminal workflows.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* REST API Endpoints */}
            <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-neutral-800 pb-2">
                <span className="font-bold text-white uppercase text-[11px]">Primary REST Endpoints</span>
                <span className="text-cyan-400 text-[10px]">FastAPI v1.0</span>
              </div>

              <div className="space-y-2 text-[11px]">
                <div className="p-2.5 rounded-lg bg-black/50 border border-neutral-800 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold text-[9px]">POST</span>
                    <code className="text-white">/scan/start</code>
                  </div>
                  <p className="text-slate-400 text-[10px]">Dispatches a 5-phase pentest job. Accepts target, engines, and scope allowlists.</p>
                </div>

                <div className="p-2.5 rounded-lg bg-black/50 border border-neutral-800 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-bold text-[9px]">GET</span>
                    <code className="text-white">/scan/status/&#123;scan_id&#125;</code>
                  </div>
                  <p className="text-slate-400 text-[10px]">Polls real-time scan progress percentage, active phase, live findings, and ETA.</p>
                </div>

                <div className="p-2.5 rounded-lg bg-black/50 border border-neutral-800 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-bold text-[9px]">GET</span>
                    <code className="text-white">/scan/results/&#123;scan_id&#125;</code>
                  </div>
                  <p className="text-slate-400 text-[10px]">Retrieves finalized correlated findings, severity counts, and RAG CVE verdicts.</p>
                </div>

                <div className="p-2.5 rounded-lg bg-black/50 border border-neutral-800 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 font-bold text-[9px]">POST</span>
                    <code className="text-white">/mcp/invoke</code>
                  </div>
                  <p className="text-slate-400 text-[10px]">Model Context Protocol endpoint for external AI agents querying tools & intel.</p>
                </div>
              </div>
            </div>

            {/* CLI Example */}
            <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-5 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-neutral-800 pb-2">
                <span className="font-bold text-white uppercase text-[11px]">Command Line Engine (CLI)</span>
                <button
                  onClick={() => handleCopy("python cli.py --target https://scanme.nmap.org --profile full --in-scope '*.nmap.org'", "cli")}
                  className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-white cursor-pointer"
                >
                  {copiedCode === "cli" ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                  <span>{copiedCode === "cli" ? "Copied" : "Copy Command"}</span>
                </button>
              </div>

              <div className="bg-black/70 p-3 rounded-xl border border-neutral-800 text-[11px] text-slate-300 overflow-x-auto">
                <pre>{`# Run full automated assessment against target
python cli.py --target https://scanme.nmap.org \\
              --profile full \\
              --in-scope "*.nmap.org" \\
              --out-of-scope "admin.nmap.org" \\
              --export-pdf report.pdf`}</pre>
              </div>

              <div className="space-y-1 text-slate-400 text-[11px]">
                <p>• Automatically connects to the local Ollama LLM if available.</p>
                <p>• Generates executive PDF reports with zero third-party dependencies.</p>
                <p>• Returns clean Linux exit codes (0 = clean, 1 = high/critical found).</p>
              </div>
            </div>
          </div>
        </section>

        {/* SECTION 8: ROADMAP & CAPSTONE GOVERNANCE */}
        <section id="roadmap" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <FolderGit2 size={14} />
              <span>// 08 PROJECT ROADMAP & TEAM</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Academic Capstone Roadmap & Governance
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Track project milestones across Semesters 6, 7, and 8 leading up to production hardening and thesis submission.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 font-mono text-xs">
            <div className="rounded-2xl border border-emerald-500/30 bg-emerald-950/15 p-5 space-y-3">
              <span className="text-emerald-400 font-bold uppercase text-[11px] block">Semester 6: Foundation (Completed)</span>
              <ul className="space-y-1.5 text-slate-300 text-[11px]">
                <li className="flex items-center gap-1.5"><Check size={12} className="text-emerald-400" /> Project repository & CI/CD workflow</li>
                <li className="flex items-center gap-1.5"><Check size={12} className="text-emerald-400" /> Multi-tool baseline containerization</li>
                <li className="flex items-center gap-1.5"><Check size={12} className="text-emerald-400" /> Fast-forward report generator (PDF)</li>
                <li className="flex items-center gap-1.5"><Check size={12} className="text-emerald-400" /> Initial semester demonstration</li>
              </ul>
            </div>

            <div className="rounded-2xl border border-cyan-500/30 bg-cyan-950/15 p-5 space-y-3">
              <span className="text-cyan-400 font-bold uppercase text-[11px] block">Semester 7: Core AI & RAG (Current)</span>
              <ul className="space-y-1.5 text-slate-300 text-[11px]">
                <li className="flex items-center gap-1.5"><Check size={12} className="text-cyan-400" /> Ollama Qwen 2.5:7b template selector</li>
                <li className="flex items-center gap-1.5"><Check size={12} className="text-cyan-400" /> ChromaDB vector database (5k+ chunks)</li>
                <li className="flex items-center gap-1.5"><Check size={12} className="text-cyan-400" /> Redamon interactive workflow canvas</li>
                <li className="flex items-center gap-1.5"><Check size={12} className="text-cyan-400" /> HexStrike MCP toolchain server</li>
              </ul>
            </div>

            <div className="rounded-2xl border border-purple-500/30 bg-purple-950/15 p-5 space-y-3">
              <span className="text-purple-400 font-bold uppercase text-[11px] block">Semester 8: Hardening & Capstone</span>
              <ul className="space-y-1.5 text-slate-300 text-[11px]">
                <li className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-purple-400" /> Full end-to-end multi-target stress testing</li>
                <li className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-purple-400" /> Security hardening & SELinux certification</li>
                <li className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-purple-400" /> Executive thesis report & public presentation</li>
                <li className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-purple-400" /> Open-source release & final submission</li>
              </ul>
            </div>
          </div>
        </section>

        {/* SECTION 9: DEPLOYMENT & QUICKSTART */}
        <section id="quickstart" className="space-y-6 scroll-mt-20">
          <div className="border-b border-cyan-500/20 pb-4">
            <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
              <Server size={14} />
              <span>// 09 QUICK DEPLOYMENT</span>
            </div>
            <h2 className="text-2xl lg:text-3xl font-extrabold text-white mt-1">
              Docker Compose & Native Quickstart
            </h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Get the complete stack running locally in under 3 minutes with Docker Compose.
            </p>
          </div>

          <div className="rounded-2xl border border-neutral-800 bg-[#090b14] p-6 space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="text-white font-bold">1. Clone & Spin up with Docker Compose</span>
              <button
                onClick={() => handleCopy("git clone https://github.com/haridevp/ORVYN.git\ncd ORVYN\ndocker compose up --build -d", "docker")}
                className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-white cursor-pointer"
              >
                {copiedCode === "docker" ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                <span>{copiedCode === "docker" ? "Copied" : "Copy"}</span>
              </button>
            </div>
            <div className="bg-black/70 p-4 rounded-xl border border-neutral-800 text-slate-200">
              <pre>{`# Clone the ORVYN repository
git clone https://github.com/haridevp/ORVYN.git
cd ORVYN

# Build and start all services (Backend, Frontend, Postgres, Redis)
docker compose up --build -d`}</pre>
            </div>

            <div className="pt-2 flex flex-wrap items-center justify-between gap-4 text-slate-400 text-[11px]">
              <div>
                <span>• Web Cyber-Deck: </span>
                <a href="http://localhost:5173" target="_blank" rel="noreferrer" className="text-cyan-400 underline">
                  http://localhost:5173
                </a>
              </div>
              <div>
                <span>• FastAPI Backend Swagger: </span>
                <a href="http://localhost:8000/docs" target="_blank" rel="noreferrer" className="text-cyan-400 underline">
                  http://localhost:8000/docs
                </a>
              </div>
              <div>
                <span>• HexStrike MCP Server: </span>
                <code className="text-purple-300">http://localhost:8000/mcp</code>
              </div>
            </div>
          </div>
        </section>

      </main>

      {/* 4. FOOTER */}
      <footer className="border-t border-neutral-800 bg-[#05060a] px-4 lg:px-8 py-10 mt-20">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6 text-xs font-mono text-slate-400">
          <div className="flex items-center gap-3">
            <div className="h-6 w-6 rounded bg-cyan-950 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold text-xs">
              O
            </div>
            <div>
              <span className="text-white font-bold">ORVYN</span> — Offensive Risk & Vulnerability Intelligence Network
              <p className="text-[10px] text-slate-500">Autonomous Pentest & Security RAG Platform • MIT Academic License</p>
            </div>
          </div>

          <div className="flex items-center gap-4 text-[11px]">
            <button
              onClick={onLaunchApp}
              className="text-cyan-400 hover:text-white transition-colors cursor-pointer"
            >
              Launch Cyber-Deck App
            </button>
            <span>•</span>
            <a
              href="https://github.com/haridevp/ORVYN"
              target="_blank"
              rel="noreferrer"
              className="hover:text-white transition-colors"
            >
              GitHub Repository
            </a>
            <span>•</span>
            <button
              onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
              className="hover:text-white transition-colors cursor-pointer"
            >
              Back to Top ↑
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
