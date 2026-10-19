import { useState } from "react";
import type { ScannerProgress, ScannerFinding, LLMDecision, RAGComparisonSummary } from "../types";
import { RunStateBadge, SeverityBadge } from "./Badge";
import { ToolMonogram, toolLabel } from "./ToolBadge";
import { motion, AnimatePresence } from "framer-motion";
import {
  Terminal,
  ShieldCheck,
  Activity,
  Clock,
  Hourglass,
  CheckCircle2,
  StopCircle,
  XCircle,
  ChevronDown,
  ChevronUp,
  Brain,
  Zap,
  Scale,
  Sparkles,
  Layers,
  Search,
  Tag,
  AlertCircle,
  Check,
  GitBranch,
  List,
} from "lucide-react";
import { RedamonWorkflowGraph } from "./RedamonWorkflowGraph";

interface ScannerProgressListProps {
  scanners: ScannerProgress[];
  onOpenTerminal?: () => void;
  terminalOpen?: boolean;
  onCancelScan?: () => void;
  logsCount?: number;
  progressPct?: number;
  etaSeconds?: number | null;
  elapsedSeconds?: number;
  overallStatus?: string;
  currentPhase?: string | null;
  llmDecision?: LLMDecision | null;
  ragComparison?: RAGComparisonSummary | null;
  liveFindings?: ScannerFinding[];
  allLogs?: string[];
  target?: string;
}

function formatSeconds(secs: number): string {
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
}

function formatEta(eta: number): string {
  if (eta <= 0) return "Finalizing...";
  if (eta <= 2) return "Finishing up...";
  if (eta < 60) return `~${eta}s`;
  const m = Math.floor(eta / 60);
  const s = eta % 60;
  return s > 0 ? `~${m}m ${s}s` : `~${m}m`;
}

interface PipelinePhaseInfo {
  id: string;
  number: number;
  title: string;
  shortLabel: string;
  desc: string;
  icon: typeof Search;
}

const PIPELINE_PHASES: PipelinePhaseInfo[] = [
  {
    id: "initial_scanning",
    number: 1,
    title: "Initial Scanning",
    shortLabel: "Recon & Baseline",
    desc: "Perimeter fingerprinting with Nmap, WhatWeb, SSLyze, Nikto, and ZAP",
    icon: Search,
  },
  {
    id: "llm_template_selection",
    number: 2,
    title: "LLM Template Selection",
    shortLabel: "AI Recon Validation",
    desc: "Qwen 2.5 analyzes perimeter data to select targeted audit template & tools",
    icon: Brain,
  },
  {
    id: "targeted_tool_execution",
    number: 3,
    title: "Targeted Tool Execution",
    shortLabel: "Targeted Scans",
    desc: "Running Nuclei with LLM-selected tags and dynamic secondary attack engines",
    icon: Zap,
  },
  {
    id: "rag_triage",
    number: 4,
    title: "RAG Comparison & Triage",
    shortLabel: "Knowledge Base Validation",
    desc: "Validating against 5k+ ChromaDB vector base with authoritative CVE/CWE citations",
    icon: Scale,
  },
  {
    id: "completed",
    number: 5,
    title: "Final Results",
    shortLabel: "Correlated Report",
    desc: "Autonomous correlation, deduplication, and verified vulnerability report",
    icon: Sparkles,
  },
];

export function ScannerProgressList({
  scanners,
  onOpenTerminal,
  terminalOpen,
  onCancelScan,
  logsCount = 0,
  progressPct = 0,
  etaSeconds,
  elapsedSeconds = 0,
  overallStatus = "running",
  currentPhase = "initial_scanning",
  llmDecision,
  ragComparison,
  liveFindings = [],
  allLogs = [],
  target,
}: ScannerProgressListProps) {
  const isCompleted = overallStatus === "completed";
  const isCancelled = overallStatus === "cancelled";
  const isFinished = isCompleted || isCancelled;
  const pct = isFinished ? 100 : Math.max(0, Math.min(100, progressPct));

  // Determine current active phase index (0 to 4)
  const activePhaseId = isCompleted ? "completed" : (currentPhase || "initial_scanning");
  const currentPhaseIndex = Math.max(
    0,
    PIPELINE_PHASES.findIndex((p) => p.id === activePhaseId)
  );

  // Accordion state for expandable engine rows
  const [expandedEngines, setExpandedEngines] = useState<Record<string, boolean>>({});
  const [showLlmCard, setShowLlmCard] = useState<boolean>(true);
  const [showRagCard, setShowRagCard] = useState<boolean>(true);
  const [viewMode, setViewMode] = useState<"workflow" | "telemetry">("workflow");

  const toggleEngine = (tool: string) => {
    setExpandedEngines((prev) => ({
      ...prev,
      [tool]: !prev[tool],
    }));
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="enterprise-panel p-5 space-y-5"
    >
      {/* 1. TOP HEADER & TELEMETRY CONTROLS */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-neutral-800/80 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm">
            <Activity size={15} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xs font-bold uppercase tracking-wider text-neutral-200">
                Autonomous Pentest Pipeline
              </h2>
              <span className="rounded bg-neutral-800/80 px-2 py-0.5 text-[10px] font-mono text-neutral-400 border border-neutral-700/60">
                Phase {Math.min(5, currentPhaseIndex + 1)} of 5
              </span>
            </div>
            <span className="text-[11px] text-neutral-500">
              {scanners.filter((s) => s.status === "completed").length} of {scanners.length} engines completed
              {target ? ` • Target: ${target}` : ""}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* View Mode Toggle: Workflow Node-Graph (Redamon) vs. Phase Telemetry List */}
          <div className="flex items-center gap-1 rounded-xl bg-[#090b14] p-1 border border-cyan-500/30 shadow-inner">
            <button
              type="button"
              onClick={() => setViewMode("workflow")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
                viewMode === "workflow"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-[0_0_10px_rgba(0,240,255,0.25)]"
                  : "text-slate-400 hover:text-white"
              }`}
              title="Workflow View (Redamon Interactive Node Graph)"
            >
              <GitBranch size={13} className="text-cyan-400" />
              <span>Workflow View</span>
            </button>
            <button
              type="button"
              onClick={() => setViewMode("telemetry")}
              className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
                viewMode === "telemetry"
                  ? "bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-[0_0_10px_rgba(168,85,247,0.25)]"
                  : "text-slate-400 hover:text-white"
              }`}
              title="Phase Telemetry Stepper View"
            >
              <List size={13} className="text-purple-400" />
              <span>Phase Telemetry</span>
            </button>
          </div>

          {!isFinished && onCancelScan && (
            <button
              onClick={onCancelScan}
              className="flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 hover:bg-rose-500/20 px-3 py-1.5 text-xs font-medium text-rose-300 transition-all cursor-pointer shadow-sm"
              title="Abort and end current scan execution"
            >
              <StopCircle size={13} className="text-rose-400" />
              <span>Abort Scan</span>
            </button>
          )}

          {onOpenTerminal && (
            <button
              onClick={onOpenTerminal}
              className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition-all cursor-pointer shadow-sm ${
                terminalOpen
                  ? "border-cyan-500/40 bg-cyan-500/15 text-cyan-300"
                  : "border-neutral-800 bg-[#0c0d12] text-neutral-400 hover:border-neutral-700 hover:text-white"
              }`}
            >
              <Terminal size={13} className="text-cyan-400" />
              <span>{terminalOpen ? "Hide Console" : "Live Console"}</span>
              {logsCount > 0 && (
                <span className="rounded bg-neutral-800 px-1.5 py-0.2 text-[10px] font-mono text-neutral-400">
                  {logsCount}
                </span>
              )}
            </button>
          )}
        </div>
      </div>

      {/* 2. MAIN PIPELINE VIEW: WORKFLOW GRAPH OR STEPPER */}
      {viewMode === "workflow" ? (
        <RedamonWorkflowGraph
          scanners={scanners}
          target={target}
          isRunning={!isFinished}
          liveFindings={liveFindings}
        />
      ) : (
        /* Stepper Tracker View */
        <div className="rounded-xl border border-neutral-800/90 bg-[#07080c] p-3.5 space-y-3 shadow-inner">
          <div className="flex items-center justify-between text-[11px] text-neutral-400 border-b border-neutral-800/50 pb-2">
            <div className="flex items-center gap-1.5 font-medium text-neutral-300">
              <Layers size={13} className="text-purple-400" />
              <span>Multi-Stage Autonomous Pipeline Execution</span>
            </div>
            <span className="font-mono text-purple-300 text-[10px]">
              {isCompleted ? "All 5 Phases Complete" : PIPELINE_PHASES[currentPhaseIndex]?.desc}
            </span>
          </div>

        {/* 5-Phase Horizontal Stepper */}
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
          {PIPELINE_PHASES.map((phase, idx) => {
            const isPhaseDone = isCompleted || idx < currentPhaseIndex;
            const isPhaseActive = !isCompleted && !isCancelled && idx === currentPhaseIndex;
            const isUpcoming = !isCompleted && idx > currentPhaseIndex;
            const PhaseIcon = phase.icon;

            return (
              <div
                key={phase.id}
                className={`relative rounded-lg p-2.5 border transition-all flex flex-col justify-between ${
                  isPhaseDone
                    ? "bg-emerald-950/20 border-emerald-500/30 text-emerald-300"
                    : isPhaseActive
                    ? "bg-purple-950/30 border-purple-500/50 text-purple-200 ring-1 ring-purple-500/40 shadow-lg shadow-purple-500/10"
                    : "bg-[#0b0c11] border-neutral-800/60 text-neutral-500 opacity-60"
                }`}
              >
                <div className="flex items-center justify-between gap-1 mb-1.5">
                  <span className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold font-mono ${
                    isPhaseDone
                      ? "bg-emerald-500 text-black font-semibold"
                      : isPhaseActive
                      ? "bg-purple-500 text-white animate-pulse"
                      : "bg-neutral-800 text-neutral-400"
                  }`}>
                    {isPhaseDone ? <Check size={11} strokeWidth={3} /> : phase.number}
                  </span>

                  <PhaseIcon
                    size={14}
                    className={
                      isPhaseDone
                        ? "text-emerald-400"
                        : isPhaseActive
                        ? "text-purple-400 animate-bounce"
                        : "text-neutral-600"
                    }
                  />
                </div>

                <div>
                  <h4 className="text-[11px] font-bold leading-tight truncate">
                    {phase.title}
                  </h4>
                  <p className="text-[9.5px] text-neutral-400 truncate mt-0.5">
                    {phase.shortLabel}
                  </p>
                </div>

                {isPhaseActive && (
                  <div className="mt-2 flex items-center gap-1 text-[9px] font-semibold uppercase tracking-wider text-purple-300">
                    <span className="h-1.5 w-1.5 rounded-full bg-purple-400 animate-ping" />
                    <span>In Progress</span>
                  </div>
                )}
                {isPhaseDone && (
                  <div className="mt-2 flex items-center gap-1 text-[9px] font-semibold uppercase tracking-wider text-emerald-400">
                    <CheckCircle2 size={10} />
                    <span>Validated</span>
                  </div>
                )}
                {isUpcoming && (
                  <div className="mt-2 text-[9px] text-neutral-600 font-mono">
                    Pending
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
      )}

      {/* 3. PROGRESS & ETA TELEMETRY BAR */}
      <div className="rounded-lg border border-neutral-800 bg-[#0a0b10] p-3.5 space-y-2.5">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-white font-mono">{pct}%</span>
            <span className="text-neutral-600">•</span>
            <span className="text-neutral-400">
              {isCompleted ? (
                <span className="text-emerald-400 font-medium flex items-center gap-1">
                  <CheckCircle2 size={13} /> Assessment Completed — All Findings Correlated
                </span>
              ) : isCancelled ? (
                <span className="text-rose-400 font-medium flex items-center gap-1">
                  <XCircle size={13} /> Scan Aborted by User
                </span>
              ) : (
                <span className="text-purple-300 font-medium flex items-center gap-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-purple-400 animate-pulse" />
                  {PIPELINE_PHASES[currentPhaseIndex]?.title}: {PIPELINE_PHASES[currentPhaseIndex]?.shortLabel}
                </span>
              )}
            </span>
          </div>

          <div className="flex items-center gap-4 text-[11px] font-mono text-neutral-400">
            <div className="flex items-center gap-1.5" title="Elapsed assessment runtime">
              <Clock size={12} className="text-neutral-500" />
              <span>Elapsed: {formatSeconds(elapsedSeconds)}</span>
            </div>

            {!isFinished && etaSeconds !== undefined && etaSeconds !== null && (
              <div className="flex items-center gap-1.5 text-purple-400" title="Estimated time to complete scan">
                <Hourglass size={12} className="text-purple-400" />
                <span>ETA: {formatEta(etaSeconds)}</span>
              </div>
            )}
          </div>
        </div>

        {/* Shimmer Bar */}
        <div className="relative h-2 w-full overflow-hidden rounded-full bg-neutral-900 border border-neutral-800">
          <motion.div
            className={`h-full rounded-full ${
              isCompleted
                ? "bg-gradient-to-r from-emerald-600 to-emerald-400"
                : "bg-gradient-to-r from-purple-600 via-indigo-500 to-purple-400"
            }`}
            initial={{ width: 0 }}
            animate={{ width: `${pct}%` }}
            transition={{ duration: 0.4, ease: "easeOut" }}
          />
          {!isCompleted && pct < 100 && (
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent animate-progress-shimmer pointer-events-none" />
          )}
        </div>
      </div>

      {/* 4. AUTONOMOUS LLM DECISION CARD (PHASE 2 & BEYOND) */}
      {llmDecision && (
        <div className="rounded-xl border border-purple-500/30 bg-[#090a10] overflow-hidden">
          <div
            onClick={() => setShowLlmCard(!showLlmCard)}
            className="flex items-center justify-between px-4 py-3 bg-purple-950/20 hover:bg-purple-950/30 cursor-pointer border-b border-purple-500/20 transition-all"
          >
            <div className="flex items-center gap-2.5">
              <div className="flex h-6 w-6 items-center justify-center rounded-md bg-purple-500/20 text-purple-300 border border-purple-500/30">
                <Brain size={14} />
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-neutral-200">
                  Phase 2 LLM Decision: {llmDecision.template_name}
                </span>
                <span className="rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.2 text-[10px] font-mono font-semibold">
                  {llmDecision.confidence}% confidence
                </span>
                <span className="text-[10px] font-mono text-neutral-500">
                  [{llmDecision.model_name || "qwen2.5:7b"}]
                </span>
              </div>
            </div>

            <button className="text-neutral-400 hover:text-white transition-colors">
              {showLlmCard ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
            </button>
          </div>

          <AnimatePresence>
            {showLlmCard && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="p-4 space-y-3 text-xs"
              >
                {/* Rationale Quote */}
                <div className="rounded-lg bg-[#0e0f16] border border-purple-500/20 p-3 text-neutral-300 italic border-l-4 border-l-purple-500">
                  "{llmDecision.reasoning}"
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                  {/* Recommended Nuclei Tags */}
                  {llmDecision.recommended_nuclei_tags && llmDecision.recommended_nuclei_tags.length > 0 && (
                    <div className="space-y-1.5">
                      <span className="text-[11px] font-semibold text-neutral-400 flex items-center gap-1.5">
                        <Tag size={12} className="text-purple-400" />
                        Targeted Nuclei Template Tags:
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {llmDecision.recommended_nuclei_tags.map((tag) => (
                          <span
                            key={tag}
                            className="rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 px-2 py-0.5 text-[10px] font-mono font-medium"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Secondary Tools Launched */}
                  {llmDecision.recommended_tools && llmDecision.recommended_tools.length > 0 && (
                    <div className="space-y-1.5">
                      <span className="text-[11px] font-semibold text-neutral-400 flex items-center gap-1.5">
                        <Zap size={12} className="text-amber-400" />
                        Autonomous Tool Chain:
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {llmDecision.recommended_tools.map((tool) => (
                          <span
                            key={tool}
                            className="rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 px-2 py-0.5 text-[10px] font-mono font-semibold uppercase"
                          >
                            {tool}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* 5. RAG KNOWLEDGE BASE VALIDATION SUMMARY (PHASE 4 & BEYOND) */}
      {ragComparison && (
        <div className="rounded-xl border border-emerald-500/30 bg-[#070b09] overflow-hidden">
          <div
            onClick={() => setShowRagCard(!showRagCard)}
            className="flex items-center justify-between px-4 py-3 bg-emerald-950/20 hover:bg-emerald-950/30 cursor-pointer border-b border-emerald-500/20 transition-all"
          >
            <div className="flex items-center gap-2.5">
              <div className="flex h-6 w-6 items-center justify-center rounded-md bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                <Scale size={14} />
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-neutral-200">
                  Phase 4 RAG Validation: {ragComparison.confirmed_count} Confirmed Vulnerabilities
                </span>
                <span className="rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.2 text-[10px] font-mono font-semibold">
                  {ragComparison.citations_count} Citations Linked
                </span>
              </div>
            </div>

            <button className="text-neutral-400 hover:text-white transition-colors">
              {showRagCard ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
            </button>
          </div>

          <AnimatePresence>
            {showRagCard && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="p-4 space-y-3 text-xs"
              >
                {/* Stats row */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
                  <div className="rounded-lg bg-[#09100c] border border-emerald-500/20 p-2">
                    <span className="text-[10px] text-neutral-500 block uppercase">Validated</span>
                    <span className="text-base font-bold text-white font-mono">{ragComparison.total_validated}</span>
                  </div>
                  <div className="rounded-lg bg-[#09100c] border border-emerald-500/20 p-2">
                    <span className="text-[10px] text-emerald-400 block uppercase">Confirmed Genuine</span>
                    <span className="text-base font-bold text-emerald-300 font-mono">{ragComparison.confirmed_count}</span>
                  </div>
                  <div className="rounded-lg bg-[#09100c] border border-blue-500/20 p-2">
                    <span className="text-[10px] text-blue-400 block uppercase">Informational</span>
                    <span className="text-base font-bold text-blue-300 font-mono">{ragComparison.informational_count}</span>
                  </div>
                  <div className="rounded-lg bg-[#09100c] border border-purple-500/20 p-2">
                    <span className="text-[10px] text-purple-400 block uppercase">Authoritative Citations</span>
                    <span className="text-base font-bold text-purple-300 font-mono">{ragComparison.citations_count}</span>
                  </div>
                </div>

                {/* Knowledge Base Matches List */}
                {ragComparison.knowledge_base_matches && ragComparison.knowledge_base_matches.length > 0 && (
                  <div className="space-y-2 pt-1">
                    <span className="text-[11px] font-semibold text-neutral-300 block">
                      Authoritative Standard Comparisons (ChromaDB / CWE Top 25 / OWASP):
                    </span>
                    <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                      {ragComparison.knowledge_base_matches.map((match, idx) => (
                        <div
                          key={idx}
                          className="rounded-lg bg-[#0c130f] border border-neutral-800 p-2.5 flex flex-col gap-1 text-[11px]"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-semibold text-neutral-200 truncate">
                              {match.vulnerability}
                            </span>
                            <span className={`text-[10px] font-mono px-2 py-0.2 rounded border ${
                              match.verdict.includes("CONFIRMED")
                                ? "bg-rose-500/10 text-rose-300 border-rose-500/30"
                                : "bg-neutral-800 text-neutral-400 border-neutral-700"
                            }`}>
                              {match.verdict} ({match.confidence}%)
                            </span>
                          </div>

                          <div className="flex flex-wrap items-center gap-2 text-[10px] text-neutral-400 font-mono">
                            {match.cwe_citations && match.cwe_citations[0] && (
                              <span className="text-purple-300 bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/20">
                                {match.cwe_citations[0].split(" (")[0]}
                              </span>
                            )}
                            {match.owasp_citations && match.owasp_citations[0] && (
                              <span className="text-blue-300 bg-blue-500/10 px-1.5 py-0.5 rounded border border-blue-500/20">
                                {match.owasp_citations[0].split(" (")[0]}
                              </span>
                            )}
                            {match.cve_citations && match.cve_citations[0] && (
                              <span className="text-amber-300 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                                {match.cve_citations[0]}
                              </span>
                            )}
                          </div>

                          {match.reasoning && (
                            <p className="text-neutral-400 text-[10px] line-clamp-1 italic">
                              Judge: {match.reasoning}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* 6. ENGINE STATUS ROWS WITH INTERACTIVE ACCORDION DROPDOWN */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs text-neutral-400 px-1">
          <span className="font-semibold text-neutral-300">Scanner Engine Telemetry</span>
          <span className="text-[11px] text-neutral-500">Click arrow on any engine to inspect live findings & logs</span>
        </div>

        <div className="flex flex-col gap-2">
          {scanners.map((s) => {
            const isExpanded = !!expandedEngines[s.tool];
            const engineFindings = liveFindings.filter((f) => f.tool === s.tool);
            const engineLogs = allLogs.filter((l) => l.toLowerCase().includes(`[${s.tool.toLowerCase()}]`));

            return (
              <div
                key={s.tool}
                className="rounded-lg border border-neutral-800/80 bg-[#0a0b10] overflow-hidden transition-all hover:border-neutral-700/80"
              >
                {/* Main Engine Row */}
                <div
                  onClick={() => toggleEngine(s.tool)}
                  className="flex items-center justify-between px-3.5 py-2.5 cursor-pointer hover:bg-neutral-900/40 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <ToolMonogram tool={s.tool} />
                    <span className="text-xs font-semibold text-neutral-200">
                      {toolLabel(s.tool)}
                    </span>

                    {s.status === "running" && (
                      <span className="flex items-center gap-1 rounded border border-purple-500/20 bg-purple-500/10 px-1.5 py-0.5 text-[10px] font-medium text-purple-300">
                        <span className="h-1 w-1 rounded-full bg-purple-400 animate-pulse" />
                        executing
                      </span>
                    )}

                    {s.status === "completed" && (
                      s.simulated ? (
                        <span className="rounded border border-amber-500/20 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-400">
                          simulated
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 rounded border border-emerald-500/20 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-400">
                          <ShieldCheck size={11} />
                          real engine
                        </span>
                      )
                    )}
                  </div>

                  <div className="flex items-center gap-3">
                    {(s.findings_count > 0 || s.status === "completed") && (
                      <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                        s.findings_count > 0 
                          ? "bg-rose-500/10 text-rose-300 border-rose-500/20 font-semibold" 
                          : "bg-neutral-900 text-neutral-400 border-neutral-800"
                      }`}>
                        {s.findings_count} finding{s.findings_count === 1 ? "" : "s"}
                      </span>
                    )}
                    {s.status === "error" && s.error && (
                      <span className="text-xs text-rose-400 truncate max-w-xs">{s.error}</span>
                    )}
                    <RunStateBadge state={s.status} />

                    {/* Interactive Dropdown Arrow */}
                    <div
                      className={`p-1 rounded hover:bg-neutral-800 text-neutral-400 hover:text-white transition-all transform ${
                        isExpanded ? "rotate-180 text-purple-400" : ""
                      }`}
                    >
                      <ChevronDown size={14} />
                    </div>
                  </div>
                </div>

                {/* Dropdown Accordion Panel */}
                <AnimatePresence>
                  {isExpanded && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      className="border-t border-neutral-800/80 bg-[#07080d] p-3.5 space-y-3"
                    >
                      {/* Section A: Discovered Findings for this Engine */}
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-semibold text-neutral-300 flex items-center gap-1.5">
                            <AlertCircle size={12} className="text-rose-400" />
                            Discovered Findings ({engineFindings.length}):
                          </span>
                          <span className="text-[10px] font-mono text-neutral-500">
                            Tool: {s.tool.toUpperCase()}
                          </span>
                        </div>

                        {engineFindings.length === 0 ? (
                          <div className="rounded-lg bg-[#0b0c12] border border-neutral-800/60 p-3 text-center text-xs text-neutral-500">
                            {s.status === "running"
                              ? "Engine actively inspecting target perimeter... Live findings will populate here."
                              : "No security vulnerabilities or exposures identified by this engine on target perimeter."}
                          </div>
                        ) : (
                          <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                            {engineFindings.map((f, fIdx) => (
                              <div
                                key={f.id || fIdx}
                                className="rounded-lg bg-[#0b0c12] border border-neutral-800 p-2.5 space-y-1 text-xs"
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <span className="font-bold text-neutral-200">
                                    {f.vulnerability}
                                  </span>
                                  <SeverityBadge severity={f.severity} />
                                </div>
                                {f.evidence && (
                                  <p className="text-[10.5px] font-mono text-neutral-400 truncate bg-neutral-900/60 px-2 py-0.5 rounded border border-neutral-800">
                                    Evidence: {f.evidence}
                                  </p>
                                )}
                                <p className="text-[11px] text-neutral-400 line-clamp-2">
                                  {f.description}
                                </p>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Section B: Engine Execution Logs */}
                      {engineLogs.length > 0 && (
                        <div className="space-y-1.5 pt-1">
                          <span className="text-[11px] font-semibold text-neutral-400 flex items-center gap-1.5">
                            <Terminal size={12} className="text-purple-400" />
                            Live Engine Logs:
                          </span>
                          <div className="rounded-lg bg-black/80 border border-neutral-800 p-2.5 font-mono text-[10.5px] text-neutral-300 max-h-36 overflow-y-auto space-y-0.5">
                            {engineLogs.slice(-15).map((logLine, lIdx) => (
                              <div key={lIdx} className="leading-relaxed truncate">
                                {logLine}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            );
          })}
        </div>
      </div>
    </motion.div>
  );
}
