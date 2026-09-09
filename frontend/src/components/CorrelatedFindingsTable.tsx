import { useState } from "react";
import type { CorrelatedFinding, Severity } from "../types";
import { SEVERITY_STYLE } from "./Badge";
import { ToolMonogram } from "./ToolBadge";
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

function Row({ finding, index }: { finding: CorrelatedFinding; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const isDuplicate = finding.contributing_tools.length > 1;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.04 }}
      className={`group overflow-hidden rounded-xl border transition-all ${
        expanded
          ? "border-blue-500/50 bg-blue-950/20 shadow-lg shadow-blue-500/5"
          : "border-gray-800/80 bg-black/30 hover:border-gray-700 hover:bg-white/[0.02]"
      }`}
    >
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-center justify-between gap-4 px-5 py-4 text-left focus:outline-none"
      >
        <div className="flex items-center gap-4 min-w-0">
          <CvssPill severity={finding.severity} />

          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="truncate text-sm font-bold text-white tracking-wide">
                {finding.vulnerability}
              </span>
              {finding.ai_status === "completed" && (
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
              <span className="text-gray-600">•</span>
              <span className="font-mono text-xs text-gray-400 truncate max-w-xs">
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
            <span className="text-gray-500 text-[10px]">
              {finding.ai_status === 'completed' ? 'AI Validated & Triaged' : 'Triaged & Correlated'}
            </span>
          </div>

          <motion.div
            animate={{ rotate: expanded ? 180 : 0 }}
            className="text-gray-500 group-hover:text-white transition-colors"
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
            className="border-t border-gray-800/80 bg-black/60 px-6 py-5"
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="md:col-span-2 space-y-4">
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

                <div>
                  <span className="text-gray-500 uppercase tracking-wider text-[10px] font-mono">CWE / OWASP Reference</span>
                  <div className="mt-1 flex flex-wrap gap-1.5">
                    {finding.ai_references && finding.ai_references.length > 0 ? (
                      finding.ai_references.map((ref, idx) => (
                        <a
                          key={idx}
                          href={ref.startsWith("http") ? ref : `https://cwe.mitre.org/data/definitions/${ref.replace(/[^0-9]/g, "")}.html`}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1.5 font-mono text-blue-400 hover:text-blue-300 underline bg-blue-950/40 border border-blue-800/40 px-2 py-1 rounded text-[11px]"
                        >
                          <ExternalLink size={11} /> {ref}
                        </a>
                      ))
                    ) : finding.reference ? (
                      <a
                        href={finding.reference.startsWith("http") ? finding.reference : `https://cwe.mitre.org/data/definitions/${finding.reference.replace(/[^0-9]/g, "")}.html`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 font-mono text-blue-400 hover:text-blue-300 underline bg-blue-950/40 border border-blue-800/40 px-2 py-1 rounded"
                      >
                        <ExternalLink size={12} /> {finding.reference}
                      </a>
                    ) : (
                      <span className="text-gray-500 italic">OWASP Top 10 A01:2021</span>
                    )}
                  </div>
                </div>

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

  const filtered = findings.filter((f) => {
    const matchesSearch =
      f.vulnerability.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase()) ||
      f.target.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === "All" || f.severity === severityFilter.toLowerCase();
    return matchesSearch && matchesSeverity;
  });

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl border border-gray-800 bg-[#080c14]/90 shadow-2xl backdrop-blur-xl p-6"
    >
      <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white tracking-wide flex items-center gap-2">
            Correlated Findings & Vulnerabilities
            <span className="rounded-full bg-blue-950 border border-blue-700/50 px-2.5 py-0.5 text-xs font-mono text-blue-300">
              {filtered.length} of {findings.length}
            </span>
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Cross-tool de-duplicated security threats classified with CVSS scores and corroboration evidence.
          </p>
        </div>

        {/* Filters and Search */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search size={14} className="absolute left-3 top-2.5 text-gray-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search findings, CWE, target..."
              className="rounded-xl border border-gray-700/80 bg-black/50 pl-9 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:border-blue-500 focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-1 rounded-xl border border-gray-800 bg-black/40 p-1 text-xs">
            {["All", "Critical", "High", "Medium", "Low"].map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all ${
                  severityFilter === s
                    ? "bg-blue-600 text-white shadow"
                    : "text-gray-400 hover:text-white"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="flex flex-col gap-2.5">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-12 text-center text-gray-500 bg-white/[0.01] rounded-2xl border border-gray-800/60 border-dashed">
            <ShieldAlert size={36} className="mb-2 text-gray-600" />
            <p className="text-sm font-medium text-gray-400">No findings matched your search or filters.</p>
            <p className="text-xs text-gray-600 mt-1">Try selecting "All" or clearing the search query.</p>
          </div>
        ) : (
          filtered.map((f, index) => <Row key={f.correlation_id} finding={f} index={index} />)
        )}
      </div>
    </motion.div>
  );
}
