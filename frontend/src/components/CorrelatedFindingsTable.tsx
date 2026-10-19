import { useState } from "react";
import type { CorrelatedFinding, Severity } from "../types";
import { SEVERITY_STYLE } from "./Badge";
import { ToolMonogram } from "./ToolBadge";
import { RagComparisonModal } from "./RagComparisonModal";
import {
  ChevronDown,
  AlertTriangle,
  GitMerge,
  Search,
  ShieldAlert,
  Code2,
  ExternalLink,
  CheckCircle2,
  Sparkles,
  Bot,
  ShieldCheck,
  ShieldX,
  Scale,
  FileCheck,
  Database,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

function CvssPill({ severity }: { severity: Severity }) {
  const cvssMap: Record<Severity, string> = {
    critical: "9.8",
    high: "8.4",
    medium: "6.2",
    low: "3.8",
    info: "1.2",
  };

  const style = SEVERITY_STYLE[severity];
  return (
    <div
      className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-black uppercase tracking-wider font-mono border ${style.bg} ${style.color} ${style.border}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse"></span>
      <span>{severity}</span>
      <span className="opacity-70 text-[10px]">({cvssMap[severity]})</span>
    </div>
  );
}

export function RagVerdictBadge({ verdict }: { verdict?: string | null }) {
  if (!verdict) return null;
  const v = verdict.toUpperCase();
  if (v.includes("CONFIRMED")) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/20 px-2.5 py-0.5 text-[10px] font-black uppercase tracking-wider text-emerald-300 border border-emerald-500/40">
        <ShieldCheck size={11} className="text-emerald-400" />
        RAG Confirmed
      </span>
    );
  }
  if (v.includes("SUSPECTED")) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/20 px-2.5 py-0.5 text-[10px] font-black uppercase tracking-wider text-amber-300 border border-amber-500/40">
        <AlertTriangle size={11} className="text-amber-400" />
        RAG Suspected
      </span>
    );
  }
  if (v.includes("FALSE_POSITIVE")) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-slate-500/20 px-2.5 py-0.5 text-[10px] font-black uppercase tracking-wider text-slate-300 border border-slate-500/40">
        <ShieldX size={11} className="text-slate-400" />
        False Positive
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-cyan-500/20 px-2.5 py-0.5 text-[10px] font-black uppercase tracking-wider text-cyan-300 border border-cyan-500/40">
      <Scale size={11} className="text-cyan-400" />
      {verdict.replace(/_/g, " ")}
    </span>
  );
}

function Row({
  finding,
  index,
  onOpenRag,
}: {
  finding: CorrelatedFinding;
  index: number;
  onOpenRag: (finding: CorrelatedFinding) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const isDuplicate = finding.contributing_tools.length > 1;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
      className={`group overflow-hidden rounded-xl border transition-all ${
        expanded
          ? "border-purple-500/50 bg-[#0c0d12] shadow-lg shadow-purple-950/20"
          : "border-neutral-800/80 bg-[#07080c] hover:border-neutral-700 hover:bg-neutral-900/40"
      }`}
    >
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left focus:outline-none cursor-pointer"
      >
        <div className="flex items-center gap-4 min-w-0">
          <CvssPill severity={finding.severity} />

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="truncate text-sm font-bold text-white tracking-wide">
                {finding.vulnerability}
              </span>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onOpenRag(finding);
                }}
                className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-purple-500/15 hover:bg-purple-500/30 border border-purple-500/30 text-purple-300 font-mono text-[10px] font-semibold transition-all cursor-pointer"
                title="View RAG comparison and database citations"
              >
                <Database size={11} className="text-purple-400" />
                <span>RAG DB</span>
              </button>
              <RagVerdictBadge verdict={finding.ai_verdict} />
              {finding.ai_status === "completed" && !finding.ai_verdict && (
                <span className="flex items-center gap-1 rounded-full bg-purple-500/20 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-purple-300 border border-purple-500/40">
                  <Sparkles size={10} className="text-purple-400 animate-pulse" />
                  AI RAG (Qwen 2.5)
                </span>
              )}
              {isDuplicate && (
                <span className="flex items-center gap-1 rounded-full bg-blue-500/20 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-blue-400 border border-blue-500/30">
                  <GitMerge size={10} />
                  {finding.contributing_tools.length}x Multi-Engine
                </span>
              )}
              {finding.conflicting_severity && (
                <span className="flex items-center gap-1 rounded-full bg-amber-500/20 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-400 border border-amber-500/30">
                  <AlertTriangle size={10} />
                  Severity Conflict
                </span>
              )}
            </div>

            <div className="mt-2 flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                {finding.contributing_tools.map((t) => (
                  <ToolMonogram key={t} tool={t} size={16} />
                ))}
              </div>
              <span className="text-neutral-600">•</span>
              <span className="font-mono text-xs text-neutral-400 truncate max-w-xs">
                {finding.evidence[0] || finding.target}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4 shrink-0">
          <div className="hidden sm:flex flex-col items-end text-right font-mono text-[11px]">
            <span className={`${finding.ai_status === 'completed' ? 'text-purple-300' : 'text-emerald-400'} font-bold flex items-center gap-1`}>
              {finding.ai_status === 'completed' ? <Sparkles size={12} className="text-purple-400" /> : <CheckCircle2 size={12} />}
              {finding.ai_confidence ?? finding.confidence}% Confidence
            </span>
            <span className="text-neutral-500 text-[10px]">
              {finding.ai_verdict ? `RAG: ${finding.ai_verdict}` : finding.ai_status === 'completed' ? 'AI Validated & Triaged' : 'Triaged & Correlated'}
            </span>
          </div>

          <motion.div
            animate={{ rotate: expanded ? 180 : 0 }}
            className="text-neutral-500 group-hover:text-white transition-colors"
          >
            <ChevronDown size={18} />
          </motion.div>
        </div>
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-t border-neutral-800 bg-[#08090d] px-6 py-5"
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="md:col-span-2 space-y-4">
                {finding.ai_judge_reasoning && (
                  <div className="rounded-xl border border-indigo-500/40 bg-indigo-950/25 p-4">
                    <div className="flex items-center justify-between gap-2">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-300 font-mono flex items-center gap-1.5">
                        <Scale size={14} className="text-indigo-400" /> RAG Security Judge Assessment & Verdict
                      </h4>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onOpenRag(finding);
                          }}
                          className="flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 text-purple-200 text-[11px] font-mono transition-colors cursor-pointer"
                        >
                          <Database size={11} />
                          <span>Compare with RAG DB</span>
                        </button>
                        <RagVerdictBadge verdict={finding.ai_verdict} />
                      </div>
                    </div>
                    <p className="mt-2 text-sm text-indigo-100/90 leading-relaxed font-sans">
                      {finding.ai_judge_reasoning}
                    </p>
                  </div>
                )}

                {finding.ai_threat_explanation ? (
                  <div className="rounded-xl border border-purple-500/30 bg-purple-950/20 p-4">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-purple-300 font-mono flex items-center gap-1.5">
                      <Sparkles size={14} className="text-purple-400" /> AI Threat Narrative & Exploit Analysis (Qwen 2.5)
                    </h4>
                    <p className="mt-2 text-sm text-purple-100/90 leading-relaxed font-sans">
                      {finding.ai_threat_explanation}
                    </p>
                  </div>
                ) : (
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400 font-mono">
                      Vulnerability Description & Impact
                    </h4>
                    <p className="mt-1 text-sm text-gray-300 leading-relaxed font-sans">
                      {finding.description}
                    </p>
                  </div>
                )}

                {finding.evidence.length > 0 && (
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono flex items-center gap-1.5">
                      <Code2 size={14} /> Corroborated Attack Evidence ({finding.evidence.length})
                    </h4>
                    <div className="mt-2 space-y-1.5 max-h-40 overflow-y-auto pr-1">
                      {finding.evidence.map((e, i) => (
                        <div
                          key={i}
                          className="rounded-lg bg-black/90 p-2.5 font-mono text-xs text-emerald-400 border border-gray-800 break-all select-all"
                        >
                          {e}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-4 border-l border-gray-800/80 pl-6 text-xs">
                <div>
                  <span className="text-gray-500 uppercase tracking-wider text-[10px] font-mono">Target Asset</span>
                  <div className="font-mono text-cyan-300 font-bold mt-0.5 truncate">{finding.target}</div>
                </div>

                {finding.ai_validated_severity && (
                  <div>
                    <span className="text-purple-400 uppercase tracking-wider text-[10px] font-mono flex items-center gap-1">
                      <Sparkles size={10} /> AI Validated Severity
                    </span>
                    <div className="font-mono text-white font-bold mt-0.5">{finding.ai_validated_severity}</div>
                  </div>
                )}

                {/* Cited Sources: CVE */}
                {finding.ai_cve_citations && finding.ai_cve_citations.length > 0 && (
                  <div>
                    <span className="text-rose-400 uppercase tracking-wider text-[10px] font-mono flex items-center gap-1">
                      <ShieldAlert size={11} /> Cited CVE Benchmarks
                    </span>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {finding.ai_cve_citations.map((cve, idx) => (
                        <a
                          key={idx}
                          href={`https://nvd.nist.gov/vuln/detail/${cve.trim()}`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-rose-300 hover:text-rose-200 bg-rose-950/40 border border-rose-800/40 px-2 py-0.5 rounded text-[11px] transition-colors"
                        >
                          <ExternalLink size={10} /> {cve}
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {/* Cited Sources: CWE */}
                {finding.ai_cwe_citations && finding.ai_cwe_citations.length > 0 && (
                  <div>
                    <span className="text-blue-400 uppercase tracking-wider text-[10px] font-mono flex items-center gap-1">
                      <Code2 size={11} /> Cited CWE Standards
                    </span>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {finding.ai_cwe_citations.map((cwe, idx) => {
                        const digits = cwe.replace(/[^0-9]/g, "");
                        const url = digits ? `https://cwe.mitre.org/data/definitions/${digits}.html` : "https://cwe.mitre.org/";
                        return (
                          <a
                            key={idx}
                            href={url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 font-mono text-blue-300 hover:text-blue-200 bg-blue-950/40 border border-blue-800/40 px-2 py-0.5 rounded text-[11px] transition-colors"
                          >
                            <ExternalLink size={10} /> {cwe}
                          </a>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Cited Sources: OWASP */}
                {finding.ai_owasp_citations && finding.ai_owasp_citations.length > 0 && (
                  <div>
                    <span className="text-emerald-400 uppercase tracking-wider text-[10px] font-mono flex items-center gap-1">
                      <FileCheck size={11} /> Cited OWASP Top 10
                    </span>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      {finding.ai_owasp_citations.map((owasp, idx) => (
                        <a
                          key={idx}
                          href="https://owasp.org/Top10/"
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-emerald-300 hover:text-emerald-200 bg-emerald-950/40 border border-emerald-800/40 px-2 py-0.5 rounded text-[11px] transition-colors"
                        >
                          <ExternalLink size={10} /> {owasp}
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {/* Fallback Reference if no specific RAG citations */}
                {(!finding.ai_cve_citations || finding.ai_cve_citations.length === 0) &&
                 (!finding.ai_cwe_citations || finding.ai_cwe_citations.length === 0) &&
                 (!finding.ai_owasp_citations || finding.ai_owasp_citations.length === 0) && (
                  <div>
                    <span className="text-gray-500 uppercase tracking-wider text-[10px] font-mono">Reference</span>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {finding.reference ? (
                        <a
                          href={finding.reference.startsWith("http") ? finding.reference : `https://cwe.mitre.org/data/definitions/${finding.reference.replace(/[^0-9]/g, "")}.html`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1.5 font-mono text-blue-400 hover:text-blue-300 underline bg-blue-950/40 border border-blue-800/40 px-2 py-1 rounded"
                        >
                          <ExternalLink size={12} /> {finding.reference}
                        </a>
                      ) : (
                        <span className="text-gray-500 italic">OWASP Top 10 Reference</span>
                      )}
                    </div>
                  </div>
                )}

                <div>
                  <span className="text-slate-400 uppercase tracking-wider text-[10px] font-mono flex items-center gap-1">
                    <Bot size={12} className="text-purple-400" /> Remediation Guidance
                  </span>
                  <div className="mt-1 rounded-lg border border-purple-900/40 bg-purple-950/30 p-2.5 text-purple-100 text-[11px] leading-relaxed">
                    {finding.ai_remediation || "Apply input validation filter and parameterized prepared statements before routing to backend handler."}
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

    </motion.div>
  );
}

export function CorrelatedFindingsTable({ findings }: { findings: CorrelatedFinding[] }) {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("All");
  const [verdictFilter, setVerdictFilter] = useState<string>("All");

  const filtered = findings.filter((f) => {
    const matchesSearch =
      f.vulnerability.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase()) ||
      f.target.toLowerCase().includes(search.toLowerCase()) ||
      (f.ai_verdict && f.ai_verdict.toLowerCase().includes(search.toLowerCase())) ||
      (f.ai_cve_citations && f.ai_cve_citations.some((c) => c.toLowerCase().includes(search.toLowerCase()))) ||
      (f.ai_cwe_citations && f.ai_cwe_citations.some((c) => c.toLowerCase().includes(search.toLowerCase())));

    const matchesSeverity = severityFilter === "All" || f.severity === severityFilter.toLowerCase();

    let matchesVerdict = true;
    if (verdictFilter === "Confirmed") {
      matchesVerdict = Boolean(f.ai_verdict?.toUpperCase().includes("CONFIRMED"));
    } else if (verdictFilter === "Suspected") {
      matchesVerdict = Boolean(f.ai_verdict?.toUpperCase().includes("SUSPECTED"));
    } else if (verdictFilter === "False Positive") {
      matchesVerdict = Boolean(f.ai_verdict?.toUpperCase().includes("FALSE_POSITIVE"));
    }

    return matchesSearch && matchesSeverity && matchesVerdict;
  });

  const [ragModalFinding, setRagModalFinding] = useState<CorrelatedFinding | null>(null);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border border-neutral-800 bg-[#0a0b10] shadow-2xl backdrop-blur-xl p-6"
    >
      <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
            Correlated Findings & RAG Validated Threats
            <span className="rounded-full bg-purple-500/15 border border-purple-500/30 px-2.5 py-0.5 text-xs font-mono text-purple-300">
              {filtered.length} of {findings.length}
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-0.5">
            Cross-tool de-duplicated security threats triaged by RAG Validator Judge with cited CVE, CWE, and OWASP sources.
          </p>
        </div>

        {/* Filters and Search */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search size={14} className="absolute left-3 top-2.5 text-neutral-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search findings, CVE, CWE..."
              className="rounded-xl border border-neutral-800 bg-black/60 pl-9 pr-3 py-1.5 text-xs text-neutral-200 placeholder-neutral-500 focus:border-white focus:outline-none font-mono"
            />
          </div>

          <div className="flex items-center gap-1 rounded-xl border border-neutral-800 bg-black/40 p-1 text-xs">
            {["All", "Critical", "High", "Medium", "Low"].map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  severityFilter === s
                    ? "bg-white text-black font-bold shadow"
                    : "text-neutral-400 hover:text-white"
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 rounded-xl border border-neutral-800 bg-black/40 p-1 text-xs">
            {["All", "Confirmed", "Suspected", "False Positive"].map((v) => (
              <button
                key={v}
                onClick={() => setVerdictFilter(v)}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  verdictFilter === v
                    ? "bg-purple-600 text-white shadow font-bold"
                    : "text-neutral-400 hover:text-white"
                }`}
              >
                {v}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-2.5">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-12 text-center text-neutral-500 bg-white/[0.01] rounded-2xl border border-neutral-800 border-dashed">
            <ShieldAlert size={36} className="mb-2 text-neutral-600" />
            <p className="text-sm font-medium text-neutral-400">No findings matched your search or filters.</p>
            <p className="text-xs text-neutral-600 mt-1">Try selecting "All" or clearing the search query.</p>
          </div>
        ) : (
          filtered.map((f, index) => (
            <Row
              key={f.correlation_id}
              finding={f}
              index={index}
              onOpenRag={(finding) => setRagModalFinding(finding)}
            />
          ))
        )}
      </div>

      {/* RAG Results Comparison Modal */}
      <RagComparisonModal
        finding={ragModalFinding}
        isOpen={!!ragModalFinding}
        onClose={() => setRagModalFinding(null)}
      />
    </motion.div>
  );
}
