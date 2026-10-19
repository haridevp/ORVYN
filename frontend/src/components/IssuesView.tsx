import { useState } from "react";
import type { CorrelatedFinding, Severity, SeverityDistribution } from "../types";
import { RagVerdictBadge } from "./CorrelatedFindingsTable";
import { RagComparisonModal } from "./RagComparisonModal";
import { SEVERITY_STYLE } from "./Badge";
import { ToolMonogram } from "./ToolBadge";
import {
  AlertTriangle,
  Search,
  ChevronDown,
  ChevronUp,
  LayoutList,
  Kanban,
  ExternalLink,
  ShieldAlert,
  Code2,
  Sparkles,
  Bot,
  Scale,
  Plus,
  Database,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

interface IssuesViewProps {
  findings: CorrelatedFinding[];
  distribution: SeverityDistribution;
  onNewPentest: () => void;
}

export function IssuesView({ findings, distribution, onNewPentest }: IssuesViewProps) {
  const [activeStatusTab, setActiveStatusTab] = useState<"all" | "open" | "in_progress" | "snoozed" | "fixed" | "ignored">("open");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("All");
  const [verdictFilter, setVerdictFilter] = useState<string>("All");
  const [viewMode, setViewMode] = useState<"list" | "board">("list");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [ragModalFinding, setRagModalFinding] = useState<CorrelatedFinding | null>(null);

  // Status mapping for interactive issues board
  const [findingStatuses, setFindingStatuses] = useState<Record<string, "open" | "in_progress" | "fixed" | "ignored">>({});

  const getStatus = (id: string) => findingStatuses[id] || "open";

  const handleUpdateStatus = (id: string, newStatus: "open" | "in_progress" | "fixed" | "ignored") => {
    setFindingStatuses((prev) => ({ ...prev, [id]: newStatus }));
  };

  const filtered = findings.filter((f) => {
    const status = getStatus(f.correlation_id);
    if (activeStatusTab !== "all" && status !== activeStatusTab) {
      return false;
    }

    const matchesSearch =
      f.vulnerability.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase()) ||
      f.target.toLowerCase().includes(search.toLowerCase()) ||
      (f.ai_verdict && f.ai_verdict.toLowerCase().includes(search.toLowerCase())) ||
      (f.ai_cve_citations && f.ai_cve_citations.some((c) => c.toLowerCase().includes(search.toLowerCase())));

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

  const openCount = findings.filter((f) => getStatus(f.correlation_id) === "open").length;
  const inProgressCount = findings.filter((f) => getStatus(f.correlation_id) === "in_progress").length;
  const fixedCount = findings.filter((f) => getStatus(f.correlation_id) === "fixed").length;
  const ignoredCount = findings.filter((f) => getStatus(f.correlation_id) === "ignored").length;

  return (
    <div className="w-full space-y-6">
      {/* Title */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight text-white font-sans">Issues</h1>
        <button
          onClick={onNewPentest}
          className="flex items-center gap-1.5 rounded-full bg-white hover:bg-neutral-200 px-4 py-2 text-xs font-bold text-black transition-all cursor-pointer shadow-md"
        >
          <Plus size={14} />
          <span>New pentest</span>
        </button>
      </div>

      {/* Severity Counters Strip (Matching Screenshot 2) */}
      <div className="flex items-center gap-8 py-2 text-xs font-mono">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-rose-500" />
          <span className="text-neutral-400">Critical</span>
          <span className="text-xl font-bold text-white ml-1 font-sans">{distribution.critical}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-orange-500" />
          <span className="text-neutral-400">High</span>
          <span className="text-xl font-bold text-white ml-1 font-sans">{distribution.high}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-amber-400" />
          <span className="text-neutral-400">Medium</span>
          <span className="text-xl font-bold text-white ml-1 font-sans">{distribution.medium}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-blue-400" />
          <span className="text-neutral-400">Low</span>
          <span className="text-xl font-bold text-white ml-1 font-sans">{distribution.low}</span>
        </div>
      </div>

      {/* Status Filter Tabs (Matching Screenshot 2) */}
      <div className="flex items-center gap-6 border-b border-neutral-800 text-xs">
        {[
          { id: "all" as const, label: "All", count: findings.length },
          { id: "open" as const, label: "Open", count: openCount },
          { id: "in_progress" as const, label: "In progress", count: inProgressCount },
          { id: "snoozed" as const, label: "Snoozed", count: 0 },
          { id: "fixed" as const, label: "Fixed", count: fixedCount },
          { id: "ignored" as const, label: "Ignored", count: ignoredCount },
        ].map((tab) => {
          const isActive = activeStatusTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveStatusTab(tab.id)}
              className={`pb-3 font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
                isActive
                  ? "border-b-2 border-white text-white font-semibold"
                  : "text-neutral-500 hover:text-neutral-300"
              }`}
            >
              <span>{tab.label}</span>
              <span className={`text-[11px] font-mono ${isActive ? "text-neutral-300" : "text-neutral-600"}`}>
                {tab.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Filter and Control Bar (Matching Screenshot 2) */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search bar */}
          <div className="relative">
            <Search size={14} className="absolute left-3 top-2.5 text-neutral-500" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search Issues... /"
              className="w-64 rounded-xl border border-neutral-800 bg-[#0c0d12] pl-9 pr-3 py-1.5 text-xs text-neutral-200 placeholder-neutral-500 focus:border-neutral-600 focus:outline-none"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="rounded-xl border border-neutral-800 bg-[#0c0d12] px-3 py-1.5 text-xs text-neutral-300 focus:border-neutral-600 focus:outline-none cursor-pointer"
          >
            <option value="All">Severity (All)</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          {/* RAG Verdict Filter */}
          <select
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
            className="rounded-xl border border-neutral-800 bg-[#0c0d12] px-3 py-1.5 text-xs text-neutral-300 focus:border-neutral-600 focus:outline-none cursor-pointer"
          >
            <option value="All">RAG Verdict (All)</option>
            <option value="Confirmed">Confirmed</option>
            <option value="Suspected">Suspected</option>
            <option value="False Positive">False Positive</option>
          </select>
        </div>

        {/* View Toggle: List | Board */}
        <div className="flex items-center rounded-xl border border-neutral-800 bg-[#0c0d12] p-1 text-xs">
          <button
            onClick={() => setViewMode("list")}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-lg font-medium transition-all ${
              viewMode === "list"
                ? "bg-neutral-800 text-white shadow-xs"
                : "text-neutral-400 hover:text-white"
            }`}
          >
            <LayoutList size={13} />
            <span>List</span>
          </button>
          <button
            onClick={() => setViewMode("board")}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-lg font-medium transition-all ${
              viewMode === "board"
                ? "bg-neutral-800 text-white shadow-xs"
                : "text-neutral-400 hover:text-white"
            }`}
          >
            <Kanban size={13} />
            <span>Board</span>
          </button>
        </div>
      </div>

      {/* Main Content: List or Board */}
      {viewMode === "list" ? (
        <div className="rounded-2xl border border-neutral-800/80 bg-[#0a0b10] overflow-hidden">
          {/* Table Header (Matching Screenshot 2) */}
          <div className="grid grid-cols-12 gap-4 px-6 py-3 border-b border-neutral-800/80 text-[11px] font-mono text-neutral-500 uppercase tracking-wider">
            <div className="col-span-2 flex items-center gap-2">
              <input type="checkbox" className="rounded border-neutral-700 bg-neutral-900" />
              <span>Severity</span>
            </div>
            <div className="col-span-5">Issue</div>
            <div className="col-span-2">CVE / Reference</div>
            <div className="col-span-1">CVSS</div>
            <div className="col-span-2 text-right">RAG Verdict</div>
          </div>

          {/* Empty State (Matching Screenshot 2) */}
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center p-16 text-center">
              <div className="p-3 rounded-2xl bg-neutral-900/60 border border-neutral-800 text-neutral-500 mb-3">
                <AlertTriangle size={28} />
              </div>
              <h3 className="text-sm font-bold text-white">No open issues</h3>
              <p className="text-xs text-neutral-400 mt-1 max-w-sm">
                Issues appear here after a pentest finishes. Run a new pentest to scan and triage vulnerabilities.
              </p>
              <button
                onClick={onNewPentest}
                className="mt-5 rounded-full bg-white hover:bg-neutral-200 px-5 py-2 text-xs font-bold text-black transition-colors cursor-pointer"
              >
                New pentest
              </button>
            </div>
          ) : (
            <div className="divide-y divide-neutral-800/60">
              {filtered.map((finding) => {
                const isExpanded = expandedId === finding.correlation_id;
                const style = SEVERITY_STYLE[finding.severity];
                const cvssMap: Record<Severity, string> = {
                  critical: "9.8",
                  high: "8.4",
                  medium: "6.2",
                  low: "3.8",
                  info: "1.2",
                };
                const primaryCve = finding.ai_cve_citations?.[0] || finding.reference || "N/A";

                return (
                  <div key={finding.correlation_id} className="transition-colors hover:bg-neutral-900/30">
                    <div
                      onClick={() => setExpandedId(isExpanded ? null : finding.correlation_id)}
                      className="grid grid-cols-12 gap-4 px-6 py-4 items-center cursor-pointer text-xs"
                    >
                      {/* Severity Pill */}
                      <div className="col-span-2 flex items-center gap-2">
                        <input
                          type="checkbox"
                          onClick={(e) => e.stopPropagation()}
                          className="rounded border-neutral-700 bg-neutral-900"
                        />
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase font-mono border ${style.bg} ${style.color} ${style.border}`}
                        >
                          {finding.severity}
                        </span>
                      </div>

                      {/* Issue & Target */}
                      <div className="col-span-5 min-w-0 pr-2">
                        <div className="font-semibold text-white truncate">{finding.vulnerability}</div>
                        <div className="flex items-center gap-2 text-[11px] text-neutral-400 font-mono mt-0.5 truncate">
                          <span>{finding.target}</span>
                          <span>•</span>
                          <div className="flex items-center gap-1">
                            {finding.contributing_tools.map((t) => (
                              <ToolMonogram key={t} tool={t} size={14} />
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* CVE */}
                      <div className="col-span-2 font-mono text-[11px] text-neutral-300 truncate">
                        {primaryCve.startsWith("CVE") ? (
                          <span className="px-1.5 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300">
                            {primaryCve}
                          </span>
                        ) : (
                          <span className="text-neutral-400">{primaryCve}</span>
                        )}
                      </div>

                      {/* CVSS */}
                      <div className="col-span-1 font-mono text-[11px] text-neutral-300">
                        {cvssMap[finding.severity]}
                      </div>

                      {/* RAG Verdict & Details Action */}
                      <div className="col-span-2 flex items-center justify-end gap-2">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setRagModalFinding(finding);
                          }}
                          className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-purple-500/10 hover:bg-purple-500/25 border border-purple-500/30 text-purple-300 font-mono text-[10px] font-semibold transition-all cursor-pointer"
                          title="Compare with RAG Database & Citations"
                        >
                          <Database size={11} className="text-purple-400" />
                          <span>RAG DB</span>
                        </button>
                        <RagVerdictBadge verdict={finding.ai_verdict} />
                        {isExpanded ? <ChevronUp size={16} className="text-neutral-500" /> : <ChevronDown size={16} className="text-neutral-500" />}
                      </div>
                    </div>

                    {/* Expanded Detail Panel */}
                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: "auto", opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          className="border-t border-neutral-800 bg-[#08090d] px-8 py-6 space-y-6 text-xs"
                        >
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                            <div className="md:col-span-2 space-y-4">
                              {/* RAG Security Judge Assessment */}
                              {finding.ai_judge_reasoning && (
                                <div className="rounded-xl border border-indigo-500/30 bg-indigo-950/20 p-4">
                                  <div className="flex items-center justify-between">
                                    <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-300 font-mono flex items-center gap-1.5">
                                      <Scale size={14} className="text-indigo-400" /> RAG Security Judge Assessment
                                    </h4>
                                    <div className="flex items-center gap-2">
                                      <button
                                        type="button"
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          setRagModalFinding(finding);
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

                              {/* Threat Narrative */}
                              {finding.ai_threat_explanation && (
                                <div className="rounded-xl border border-purple-500/30 bg-purple-950/20 p-4">
                                  <h4 className="text-xs font-bold uppercase tracking-wider text-purple-300 font-mono flex items-center gap-1.5">
                                    <Sparkles size={14} className="text-purple-400" /> AI Threat Narrative (Qwen 2.5)
                                  </h4>
                                  <p className="mt-2 text-sm text-purple-100/90 leading-relaxed">
                                    {finding.ai_threat_explanation}
                                  </p>
                                </div>
                              )}

                              {/* Evidence */}
                              {finding.evidence.length > 0 && (
                                <div>
                                  <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono flex items-center gap-1.5">
                                    <Code2 size={14} /> Corroborated Attack Evidence ({finding.evidence.length})
                                  </h4>
                                  <div className="mt-2 space-y-1.5">
                                    {finding.evidence.map((ev, i) => (
                                      <div key={i} className="rounded-lg bg-black/90 p-2.5 font-mono text-xs text-emerald-400 border border-neutral-800 break-all select-all">
                                        {ev}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>

                            {/* Citations & Status Sidebar */}
                            <div className="space-y-4 border-l border-neutral-800 pl-6 text-xs">
                              <div>
                                <span className="text-neutral-500 uppercase tracking-wider text-[10px] font-mono">Status Action</span>
                                <div className="mt-1 flex flex-wrap gap-1.5">
                                  {(["open", "in_progress", "fixed", "ignored"] as const).map((st) => (
                                    <button
                                      key={st}
                                      onClick={() => handleUpdateStatus(finding.correlation_id, st)}
                                      className={`px-2 py-1 rounded text-[11px] font-mono transition-colors ${
                                        getStatus(finding.correlation_id) === st
                                          ? "bg-white text-black font-bold"
                                          : "bg-neutral-900 border border-neutral-800 text-neutral-400 hover:text-white"
                                      }`}
                                    >
                                      {st.replace("_", " ")}
                                    </button>
                                  ))}
                                </div>
                              </div>

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
                                        className="inline-flex items-center gap-1 font-mono text-rose-300 hover:text-rose-200 bg-rose-950/40 border border-rose-800/40 px-2 py-0.5 rounded text-[11px]"
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
                                    {finding.ai_cwe_citations.map((cwe, idx) => (
                                      <a
                                        key={idx}
                                        href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/[^0-9]/g, "")}.html`}
                                        target="_blank"
                                        rel="noreferrer"
                                        className="inline-flex items-center gap-1 font-mono text-blue-300 hover:text-blue-200 bg-blue-950/40 border border-blue-800/40 px-2 py-0.5 rounded text-[11px]"
                                      >
                                        <ExternalLink size={10} /> {cwe}
                                      </a>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Remediation Guidance */}
                              <div>
                                <span className="text-neutral-400 uppercase tracking-wider text-[10px] font-mono flex items-center gap-1">
                                  <Bot size={12} className="text-purple-400" /> Remediation Guidance
                                </span>
                                <div className="mt-1 rounded-lg border border-purple-900/40 bg-purple-950/30 p-2.5 text-purple-100 text-[11px] leading-relaxed">
                                  {finding.ai_remediation || "Enforce input sanitization, parameterized queries, and strict transport security."}
                                </div>
                              </div>
                            </div>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ) : (
        /* Board View (Kanban) */
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {(["open", "in_progress", "fixed", "ignored"] as const).map((col) => {
            const colFindings = findings.filter((f) => getStatus(f.correlation_id) === col);
            return (
              <div key={col} className="rounded-2xl border border-neutral-800 bg-[#0a0b10] p-4 flex flex-col">
                <div className="flex items-center justify-between pb-3 border-b border-neutral-800 text-xs font-bold uppercase tracking-wider font-mono">
                  <span className="text-neutral-300">{col.replace("_", " ")}</span>
                  <span className="px-2 py-0.5 rounded-full bg-neutral-900 text-neutral-400 text-[10px]">
                    {colFindings.length}
                  </span>
                </div>
                <div className="mt-3 space-y-3 flex-1 overflow-y-auto max-h-[600px]">
                  {colFindings.length === 0 ? (
                    <div className="p-8 text-center text-xs text-neutral-600 italic">No {col.replace("_", " ")} issues</div>
                  ) : (
                    colFindings.map((f) => {
                      const style = SEVERITY_STYLE[f.severity];
                      return (
                        <div
                          key={f.correlation_id}
                          className="rounded-xl border border-neutral-800/80 bg-neutral-900/50 p-3 space-y-2 hover:border-neutral-700 transition-colors"
                        >
                          <div className="flex items-center justify-between">
                            <span className={`px-2 py-0.5 rounded-full text-[9px] font-bold uppercase font-mono border ${style.bg} ${style.color} ${style.border}`}>
                              {f.severity}
                            </span>
                            <RagVerdictBadge verdict={f.ai_verdict} />
                          </div>
                          <div className="font-semibold text-white text-xs">{f.vulnerability}</div>
                          <div className="text-[10px] text-neutral-400 font-mono truncate">{f.target}</div>
                          <div className="pt-2 flex items-center justify-between border-t border-neutral-800 text-[10px]">
                            <select
                              value={getStatus(f.correlation_id)}
                              onChange={(e) => handleUpdateStatus(f.correlation_id, e.target.value as any)}
                              className="rounded bg-black border border-neutral-800 px-2 py-0.5 text-neutral-300 text-[10px]"
                            >
                              <option value="open">Open</option>
                              <option value="in_progress">In Progress</option>
                              <option value="fixed">Fixed</option>
                              <option value="ignored">Ignored</option>
                            </select>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Interactive RAG Result Comparison Modal */}
      <RagComparisonModal
        finding={ragModalFinding}
        isOpen={!!ragModalFinding}
        onClose={() => setRagModalFinding(null)}
        onUpdateStatus={handleUpdateStatus}
        currentStatus={ragModalFinding ? getStatus(ragModalFinding.correlation_id) : "open"}
      />
    </div>
  );
}
