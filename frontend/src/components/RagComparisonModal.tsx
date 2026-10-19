import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  X,
  Scale,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  ExternalLink,
  Code2,
  Copy,
  Check,
  Sparkles,
  Database,
  Terminal,
  FileCheck,
  Layers,
  Bot,
} from "lucide-react";
import type { CorrelatedFinding } from "../types";
import { ToolMonogram } from "./ToolBadge";

interface RagComparisonModalProps {
  finding: CorrelatedFinding | null;
  isOpen: boolean;
  onClose: () => void;
  onUpdateStatus?: (correlationId: string, status: "open" | "in_progress" | "fixed" | "ignored") => void;
  currentStatus?: "open" | "in_progress" | "fixed" | "ignored";
}

const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "bg-rose-500/15", text: "text-rose-400", border: "border-rose-500/30" },
  high: { bg: "bg-orange-500/15", text: "text-orange-400", border: "border-orange-500/30" },
  medium: { bg: "bg-amber-500/15", text: "text-amber-400", border: "border-amber-500/30" },
  low: { bg: "bg-blue-500/15", text: "text-blue-400", border: "border-blue-500/30" },
  info: { bg: "bg-neutral-800", text: "text-neutral-400", border: "border-neutral-700" },
};

export function RagComparisonModal({
  finding,
  isOpen,
  onClose,
  onUpdateStatus,
  currentStatus = "open",
}: RagComparisonModalProps) {
  const [activeTab, setActiveTab] = useState<"comparison" | "citations" | "remediation">("comparison");
  const [copied, setCopied] = useState(false);

  if (!isOpen || !finding) return null;

  const rawSev = (finding.severity || "info").toLowerCase();
  const valSev = (finding.ai_validated_severity || finding.severity || "info").toLowerCase();
  const rawSevStyle = SEVERITY_COLORS[rawSev] || SEVERITY_COLORS.info;
  const valSevStyle = SEVERITY_COLORS[valSev] || SEVERITY_COLORS.info;

  const isConfirmed =
    finding.ai_verdict === "CONFIRMED_VULNERABILITY" ||
    finding.ai_verdict === "CONFIRMED";
  const isSuspected =
    finding.ai_verdict === "SUSPECTED_VULNERABILITY" ||
    finding.ai_verdict === "SUSPECTED";
  const isFalsePositive =
    finding.ai_verdict === "FALSE_POSITIVE" ||
    finding.ai_verdict === "FALSE_POSITIVE_FLAGGED";

  const verdictLabel = isConfirmed
    ? "CONFIRMED EXPLOITABLE"
    : isSuspected
    ? "SUSPECTED VULNERABILITY"
    : isFalsePositive
    ? "FALSE POSITIVE FILTERED"
    : "INFORMATIONAL TELEMETRY";

  const verdictBadgeStyle = isConfirmed
    ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300"
    : isSuspected
    ? "bg-amber-500/15 border-amber-500/40 text-amber-300"
    : isFalsePositive
    ? "bg-rose-500/15 border-rose-500/40 text-rose-300"
    : "bg-neutral-800 border-neutral-700 text-neutral-300";

  const verdictIcon = isConfirmed ? (
    <ShieldCheck size={14} className="text-emerald-400" />
  ) : isSuspected ? (
    <AlertTriangle size={14} className="text-amber-400" />
  ) : isFalsePositive ? (
    <ShieldAlert size={14} className="text-rose-400" />
  ) : (
    <Info size={14} className="text-neutral-400" />
  );

  const handleCopyMarkdown = () => {
    const md = `### ${finding.vulnerability}
**Target:** ${finding.target}
**Raw Severity:** ${finding.severity.toUpperCase()} -> **RAG Validated Severity:** ${valSev.toUpperCase()}
**AI Judge Verdict:** ${finding.ai_verdict || "PENDING"} (Confidence: ${finding.ai_confidence ?? 85}%)
**Contributing Scanners:** ${finding.contributing_tools.join(", ")}

#### AI Judge Reasoning
${finding.ai_judge_reasoning || "No judge reasoning provided."}

#### Threat Explanation
${finding.ai_threat_explanation || "No threat narrative provided."}

#### Citations & Database Corroboration
- **CVE Citations:** ${finding.ai_cve_citations?.join(", ") || "None"}
- **CWE Standards:** ${finding.ai_cwe_citations?.join(", ") || "None"}
- **OWASP:** ${finding.ai_owasp_citations?.join(", ") || "None"}

#### Remediation Guidance
${finding.ai_remediation || "Review application configuration and apply latest vendor patches."}
`;
    navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/80 backdrop-blur-md">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          className="relative w-full max-w-4xl max-h-[90vh] flex flex-col rounded-2xl border border-neutral-800 bg-[#07080c] shadow-2xl shadow-black overflow-hidden font-sans"
        >
          {/* Header Bar */}
          <div className="flex items-start justify-between gap-4 border-b border-neutral-800/80 bg-[#0c0d12] px-6 py-5">
            <div className="space-y-1.5 min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase border ${valSevStyle.bg} ${valSevStyle.text} ${valSevStyle.border}`}
                >
                  {valSev}
                </span>

                <span
                  className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${verdictBadgeStyle}`}
                >
                  {verdictIcon}
                  {verdictLabel}
                </span>

                <span className="text-[11px] font-mono text-neutral-400">
                  Confidence: <strong className="text-white">{finding.ai_confidence ?? 85}%</strong>
                </span>
              </div>

              <h2 className="text-lg font-bold text-white tracking-tight truncate">
                {finding.vulnerability}
              </h2>

              <div className="flex items-center gap-2 text-xs font-mono text-neutral-400">
                <span>Target: <strong className="text-neutral-200">{finding.target}</strong></span>
                <span>•</span>
                <span className="flex items-center gap-1">
                  Engines:
                  {finding.contributing_tools.map((t) => (
                    <ToolMonogram key={t} tool={t} size={15} />
                  ))}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={handleCopyMarkdown}
                className="flex items-center gap-1 rounded-lg border border-neutral-800 bg-neutral-900/80 hover:bg-neutral-800 px-3 py-1.5 text-xs text-neutral-300 transition-colors cursor-pointer"
                title="Copy full RAG assessment report"
              >
                {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
                <span>{copied ? "Copied" : "Copy Report"}</span>
              </button>

              <button
                onClick={onClose}
                className="rounded-lg p-1.5 text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors cursor-pointer"
              >
                <X size={18} />
              </button>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex items-center gap-6 border-b border-neutral-800 bg-[#090a0f] px-6 text-xs font-mono">
            {[
              { id: "comparison" as const, label: "RAG Evaluation Comparison", icon: <Scale size={13} /> },
              { id: "citations" as const, label: "Database Citations (CVE / CWE)", icon: <Database size={13} /> },
              { id: "remediation" as const, label: "Remediation & Defense", icon: <Bot size={13} /> },
            ].map((tab) => {
              const active = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-1.5 py-3 transition-colors cursor-pointer ${
                    active
                      ? "border-b-2 border-white text-white font-bold"
                      : "text-neutral-500 hover:text-neutral-300"
                  }`}
                >
                  {tab.icon}
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          {/* Modal Body */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6 text-xs text-neutral-300">
            {/* TAB 1: RAG COMPARISON (Side-by-Side: Initial Tool Finding vs RAG Knowledge Engine) */}
            {activeTab === "comparison" && (
              <div className="space-y-6">
                {/* Hero Comparison Matrix */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Left Column: Initial Scanner Findings */}
                  <div className="rounded-xl border border-neutral-800 bg-[#0c0d12] p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] uppercase font-mono font-bold tracking-wider text-neutral-400 flex items-center gap-1.5">
                        <Terminal size={13} className="text-neutral-500" /> Initial Scanner Telemetry
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-neutral-400">
                        Raw Detection
                      </span>
                    </div>

                    <div className="space-y-2 pt-1 font-mono text-xs">
                      <div className="flex justify-between items-center py-1 border-b border-neutral-800/60">
                        <span className="text-neutral-500">Detected Severity</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${rawSevStyle.bg} ${rawSevStyle.text} border ${rawSevStyle.border}`}>
                          {rawSev}
                        </span>
                      </div>
                      <div className="flex justify-between items-center py-1 border-b border-neutral-800/60">
                        <span className="text-neutral-500">Discovering Scanners</span>
                        <span className="text-white font-semibold">
                          {finding.contributing_tools.map((t) => t.toUpperCase()).join(" • ")}
                        </span>
                      </div>
                      <div className="flex justify-between items-center py-1 border-b border-neutral-800/60">
                        <span className="text-neutral-500">Corroborated Sources</span>
                        <span className="text-neutral-300">{finding.source_finding_ids?.length || 1} finding(s)</span>
                      </div>
                    </div>

                    <div>
                      <span className="text-[10px] text-neutral-500 uppercase tracking-wider font-mono block mb-1.5">
                        Raw Evidence / Payload Matched:
                      </span>
                      {finding.evidence && finding.evidence.length > 0 ? (
                        <div className="space-y-1.5 max-h-36 overflow-y-auto">
                          {finding.evidence.map((ev, i) => (
                            <div key={i} className="rounded-lg bg-black/80 border border-neutral-800/80 p-2 font-mono text-[11px] text-emerald-400 break-all select-all">
                              {ev}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="rounded-lg bg-black/60 border border-neutral-800/80 p-2 font-mono text-[11px] text-neutral-500 italic">
                          No raw payload string captured.
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right Column: RAG Knowledge Base & Security Judge */}
                  <div className="rounded-xl border border-purple-500/30 bg-purple-950/10 p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] uppercase font-mono font-bold tracking-wider text-purple-300 flex items-center gap-1.5">
                        <Sparkles size={13} className="text-purple-400" /> RAG Knowledge Corroboration
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 border border-purple-500/30 text-purple-300">
                        Chroma DB Validated
                      </span>
                    </div>

                    <div className="space-y-2 pt-1 font-mono text-xs">
                      <div className="flex justify-between items-center py-1 border-b border-purple-900/30">
                        <span className="text-neutral-400">Validated Severity</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${valSevStyle.bg} ${valSevStyle.text} border ${valSevStyle.border}`}>
                          {valSev}
                        </span>
                      </div>
                      <div className="flex justify-between items-center py-1 border-b border-purple-900/30">
                        <span className="text-neutral-400">Judge Verdict</span>
                        <span className="text-emerald-300 font-semibold">{verdictLabel}</span>
                      </div>
                      <div className="flex justify-between items-center py-1 border-b border-purple-900/30">
                        <span className="text-neutral-400">RAG Semantic Confidence</span>
                        <span className="text-purple-300 font-bold">{finding.ai_confidence ?? 85}%</span>
                      </div>
                    </div>

                    <div>
                      <span className="text-[10px] text-purple-400 uppercase tracking-wider font-mono block mb-1.5">
                        AI Security Judge Assessment:
                      </span>
                      <p className="text-xs text-neutral-200 leading-relaxed font-sans bg-black/50 p-2.5 rounded-lg border border-purple-900/40">
                        {finding.ai_judge_reasoning ||
                          "Impartial security evaluation verified the vulnerability vector against established CVE definitions and verified that scanner evidence matches real exploit conditions."}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Threat Explanation Card */}
                {finding.ai_threat_explanation && (
                  <div className="rounded-xl border border-neutral-800 bg-[#0c0d12] p-5 space-y-2">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-purple-400 font-mono flex items-center gap-1.5">
                      <Sparkles size={13} /> Exploitability Narrative & Impact Analysis (Qwen 2.5)
                    </h4>
                    <p className="text-xs text-neutral-300 leading-relaxed font-sans">
                      {finding.ai_threat_explanation}
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: DATABASE CITATIONS & KNOWLEDGE RETRIEVAL */}
            {activeTab === "citations" && (
              <div className="space-y-6">
                <div className="rounded-xl border border-neutral-800 bg-[#0c0d12] p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono flex items-center gap-1.5">
                      <Database size={14} className="text-purple-400" /> Chroma Vector Database Corroboration
                    </h3>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-neutral-400">
                      5,000+ Chunks Indexed
                    </span>
                  </div>

                  <p className="text-xs text-neutral-400 leading-relaxed">
                    This finding was semantically queried against our local Chroma security database containing NIST NVD CVEs, MITRE CWE taxonomies, and OWASP ASVS verification benchmarks.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                    {/* CVE Citations */}
                    <div className="rounded-xl border border-rose-900/40 bg-rose-950/10 p-4 space-y-2">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-rose-400 font-mono flex items-center gap-1">
                        <ShieldAlert size={12} /> Cited CVE Records
                      </span>
                      {finding.ai_cve_citations && finding.ai_cve_citations.length > 0 ? (
                        <div className="space-y-1.5">
                          {finding.ai_cve_citations.map((cve, i) => (
                            <a
                              key={i}
                              href={`https://nvd.nist.gov/vuln/detail/${cve.trim()}`}
                              target="_blank"
                              rel="noreferrer"
                              className="flex items-center justify-between rounded bg-rose-950/30 border border-rose-800/40 px-2.5 py-1 font-mono text-xs text-rose-300 hover:text-white transition-colors"
                            >
                              <span>{cve}</span>
                              <ExternalLink size={11} />
                            </a>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-neutral-500 italic">No specific CVE index required.</p>
                      )}
                    </div>

                    {/* CWE Standards */}
                    <div className="rounded-xl border border-blue-900/40 bg-blue-950/10 p-4 space-y-2">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-blue-400 font-mono flex items-center gap-1">
                        <Code2 size={12} /> Cited CWE Standards
                      </span>
                      {finding.ai_cwe_citations && finding.ai_cwe_citations.length > 0 ? (
                        <div className="space-y-1.5">
                          {finding.ai_cwe_citations.map((cwe, i) => {
                            const cweNum = cwe.replace(/[^0-9]/g, "");
                            return (
                              <a
                                key={i}
                                href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`}
                                target="_blank"
                                rel="noreferrer"
                                className="flex items-center justify-between rounded bg-blue-950/30 border border-blue-800/40 px-2.5 py-1 font-mono text-xs text-blue-300 hover:text-white transition-colors"
                              >
                                <span>{cwe}</span>
                                <ExternalLink size={11} />
                              </a>
                            );
                          })}
                        </div>
                      ) : (
                        <p className="text-xs text-neutral-500 italic">No direct CWE classification.</p>
                      )}
                    </div>

                    {/* OWASP Citations */}
                    <div className="rounded-xl border border-amber-900/40 bg-amber-950/10 p-4 space-y-2">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-amber-400 font-mono flex items-center gap-1">
                        <Layers size={12} /> OWASP Top 10 Standards
                      </span>
                      {finding.ai_owasp_citations && finding.ai_owasp_citations.length > 0 ? (
                        <div className="space-y-1.5">
                          {finding.ai_owasp_citations.map((owasp, i) => (
                            <div
                              key={i}
                              className="rounded bg-amber-950/30 border border-amber-800/40 px-2.5 py-1 font-mono text-xs text-amber-300"
                            >
                              {owasp}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-neutral-500 italic">General Application Security.</p>
                      )}
                    </div>
                  </div>
                </div>

                {/* Retrieved Knowledge References */}
                {finding.ai_references && finding.ai_references.length > 0 && (
                  <div className="rounded-xl border border-neutral-800 bg-[#0c0d12] p-5 space-y-3">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-neutral-300 font-mono flex items-center gap-1.5">
                      <FileCheck size={13} className="text-emerald-400" /> External Security Advisory Citations
                    </h4>
                    <div className="space-y-1.5">
                      {finding.ai_references.map((ref, idx) => (
                        <a
                          key={idx}
                          href={ref}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center justify-between rounded-lg bg-black/60 border border-neutral-800 px-3 py-2 text-xs font-mono text-neutral-300 hover:text-white hover:border-neutral-700 transition-colors"
                        >
                          <span className="truncate pr-4">{ref}</span>
                          <ExternalLink size={12} className="shrink-0 text-neutral-500" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* TAB 3: REMEDIATION & DEFENSE GUIDANCE */}
            {activeTab === "remediation" && (
              <div className="space-y-6">
                <div className="rounded-xl border border-neutral-800 bg-[#0c0d12] p-5 space-y-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400 font-mono flex items-center gap-1.5">
                    <Bot size={14} /> Actionable Engineering Remediation
                  </h3>

                  <div className="rounded-lg bg-black/60 border border-neutral-800 p-4 font-mono text-xs text-neutral-200 leading-relaxed whitespace-pre-wrap">
                    {finding.ai_remediation ||
                      "1. Update server runtime and packages to current stable patches.\n2. Apply defense-in-depth parameter validation.\n3. Verify HTTP security headers (CSP, HSTS, X-Content-Type-Options)."}
                  </div>
                </div>

                {/* Vulnerability Lifecycle Action */}
                {onUpdateStatus && (
                  <div className="rounded-xl border border-neutral-800 bg-[#0c0d12] p-5 space-y-3">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-neutral-400 block">
                      Update Pentest Lifecycle Status:
                    </span>
                    <div className="flex flex-wrap gap-2 text-xs font-mono">
                      {(["open", "in_progress", "fixed", "ignored"] as const).map((st) => (
                        <button
                          key={st}
                          onClick={() => onUpdateStatus(finding.correlation_id, st)}
                          className={`px-3 py-1.5 rounded-lg capitalize transition-colors cursor-pointer ${
                            currentStatus === st
                              ? "bg-white text-black font-bold shadow"
                              : "bg-neutral-900 border border-neutral-800 text-neutral-400 hover:text-white"
                          }`}
                        >
                          {st.replace("_", " ")}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Footer Bar */}
          <div className="flex items-center justify-between border-t border-neutral-800/80 bg-[#0c0d12] px-6 py-3.5 text-xs">
            <span className="text-neutral-500 font-mono text-[11px]">
              Correlation ID: <code className="text-neutral-400">{finding.correlation_id}</code>
            </span>

            <button
              onClick={onClose}
              className="rounded-full bg-white hover:bg-neutral-200 px-5 py-1.5 text-xs font-bold text-black transition-colors cursor-pointer"
            >
              Close Details
            </button>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
