import { useState } from "react";
import { motion } from "framer-motion";
import {
  History,
  Target,
  Clock,
  Trash2,
  ExternalLink,
  Search,
  Play,
  Layers,
} from "lucide-react";
import type { ScanStatusResponse } from "../types";

interface ScanHistoryViewProps {
  scans: ScanStatusResponse[];
  selectedScanId: string | null;
  onSelectScan: (scanId: string) => void;
  onDeleteScan: (scanId: string) => void;
  onNavigateToOverview: () => void;
  onNewScanClick: () => void;
}

export function ScanHistoryView({
  scans,
  selectedScanId,
  onSelectScan,
  onDeleteScan,
  onNavigateToOverview,
  onNewScanClick,
}: ScanHistoryViewProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const filteredScans = scans.filter((s) => {
    const matchesQuery =
      s.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
      s.scan_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (s.template_name && s.template_name.toLowerCase().includes(searchQuery.toLowerCase()));

    if (!matchesQuery) return false;
    if (statusFilter === "all") return true;
    if (statusFilter === "running") return s.overall_status === "running" || s.overall_status === "queued";
    if (statusFilter === "completed") return s.overall_status === "completed";
    if (statusFilter === "error") return s.overall_status === "error" || s.overall_status === "cancelled";
    return true;
  });

  const totalVulns = scans.reduce((acc, s) => acc + (s.findings_count || 0), 0);
  const activeCount = scans.filter((s) => s.overall_status === "running" || s.overall_status === "queued").length;
  const completedCount = scans.filter((s) => s.overall_status === "completed").length;

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 rounded-xl border border-neutral-800 bg-[#0a0b10] p-6 backdrop-blur-xl">
        <div className="flex items-center gap-3.5">
          <div className="p-3 bg-purple-500/10 border border-purple-500/30 rounded-xl text-purple-400">
            <History size={24} />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              Historical Assessments Catalog
              <span className="text-xs font-mono font-normal px-2 py-0.5 rounded bg-neutral-900 border border-neutral-800 text-neutral-300">
                {scans.length} recorded
              </span>
            </h2>
            <p className="text-xs text-neutral-400 mt-0.5">
              Persistent repository of past vulnerability evaluations, findings footprints, and autonomous audit logs.
            </p>
          </div>
        </div>

        <button
          onClick={onNewScanClick}
          className="flex items-center gap-2 rounded-full bg-white hover:bg-neutral-200 px-4 py-2 text-xs font-bold text-black transition-all shadow-md cursor-pointer"
        >
          <Play size={13} />
          <span>Launch New Scan</span>
        </button>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono">
        <div className="rounded-xl border border-neutral-800 bg-[#0a0b10] p-4">
          <span className="text-[10px] text-neutral-500 uppercase tracking-wider block">Total Audits</span>
          <span className="text-2xl font-bold text-white mt-1 block">{scans.length}</span>
        </div>
        <div className="rounded-xl border border-neutral-800 bg-[#0a0b10] p-4">
          <span className="text-[10px] text-neutral-500 uppercase tracking-wider block">Active Scans</span>
          <span className="text-2xl font-bold text-purple-400 mt-1 block flex items-center gap-2">
            {activeCount}
            {activeCount > 0 && <span className="h-2 w-2 rounded-full bg-purple-400 animate-ping" />}
          </span>
        </div>
        <div className="rounded-xl border border-neutral-800 bg-[#0a0b10] p-4">
          <span className="text-[10px] text-neutral-500 uppercase tracking-wider block">Completed</span>
          <span className="text-2xl font-bold text-emerald-400 mt-1 block">{completedCount}</span>
        </div>
        <div className="rounded-xl border border-neutral-800 bg-[#0a0b10] p-4">
          <span className="text-[10px] text-neutral-500 uppercase tracking-wider block">Total Vulnerabilities</span>
          <span className="text-2xl font-bold text-rose-400 mt-1 block">{totalVulns}</span>
        </div>
      </div>

      {/* Search & Filter Strip */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 rounded-lg border border-neutral-800 bg-[#0a0b10] p-3">
        <div className="relative w-full sm:w-80">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-neutral-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by target, scan ID, or template..."
            className="w-full rounded-md border border-neutral-800 bg-black/60 pl-9 pr-3 py-1.5 text-xs text-white placeholder-neutral-500 focus:border-neutral-600 focus:outline-none font-mono"
          />
        </div>

        <div className="flex items-center gap-1.5 text-xs font-mono self-end sm:self-auto">
          {(["all", "running", "completed", "error"] as const).map((filter) => (
            <button
              key={filter}
              onClick={() => setStatusFilter(filter)}
              className={`px-3 py-1 rounded-md capitalize transition-colors cursor-pointer ${
                statusFilter === filter
                  ? "bg-white text-black font-bold"
                  : "bg-neutral-900 border border-neutral-800 text-neutral-400 hover:text-white"
              }`}
            >
              {filter}
            </button>
          ))}
        </div>
      </div>

      {/* Historical Scans List */}
      {filteredScans.length === 0 ? (
        <div className="rounded-xl border border-neutral-800 bg-[#0a0b10] p-12 text-center">
          <History size={36} className="mx-auto text-neutral-600 mb-3" />
          <h3 className="text-sm font-semibold text-neutral-300">No Assessment Records Found</h3>
          <p className="text-xs text-neutral-500 mt-1 max-w-sm mx-auto">
            {searchQuery
              ? "No historical scans match your current filter parameters."
              : "Launch an automated penetration scan to begin cataloging target security evaluations."}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredScans.map((s) => {
            const isSelected = selectedScanId === s.scan_id;
            const isRunning = s.overall_status === "running" || s.overall_status === "queued";
            const dateStr = s.created_at
              ? new Date(s.created_at).toLocaleString(undefined, {
                  month: "short",
                  day: "numeric",
                  year: "numeric",
                  hour: "2-digit",
                  minute: "2-digit",
                })
              : "Unknown Date";

            const sev = (s.severity_distribution || {}) as Record<string, number>;

            return (
              <motion.div
                key={s.scan_id}
                layout
                className={`rounded-xl border p-4 transition-all ${
                  isSelected
                    ? "border-purple-500/50 bg-neutral-900 shadow-lg shadow-purple-950/20"
                    : "border-neutral-800/80 bg-[#0a0b10] hover:border-neutral-700 hover:bg-neutral-900/40"
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  {/* Left Info */}
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-semibold text-sm text-white font-mono flex items-center gap-1.5">
                        <Target size={14} className="text-purple-400" />
                        {s.target}
                      </span>

                      {/* Status Badge */}
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold ${
                          isRunning
                            ? "bg-purple-500/15 border border-purple-500/30 text-purple-300"
                            : s.overall_status === "completed"
                            ? "bg-emerald-500/15 border border-emerald-500/30 text-emerald-300"
                            : "bg-rose-500/15 border border-rose-500/30 text-rose-300"
                        }`}
                      >
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            isRunning
                              ? "bg-purple-400 animate-ping"
                              : s.overall_status === "completed"
                              ? "bg-emerald-400"
                              : "bg-rose-400"
                          }`}
                        />
                        {s.overall_status.toUpperCase()}
                      </span>

                      {isSelected && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 border border-purple-500/40 text-purple-300 font-semibold">
                          Active Selection
                        </span>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-3 text-xs text-neutral-400 font-mono">
                      <span className="text-neutral-500">ID: {s.scan_id}</span>
                      <span>•</span>
                      <span className="flex items-center gap-1">
                        <Clock size={11} className="text-neutral-500" />
                        {dateStr}
                      </span>
                      {s.template_name && (
                        <>
                          <span>•</span>
                          <span className="flex items-center gap-1 text-neutral-300">
                            <Layers size={11} className="text-purple-400" />
                            {s.template_name}
                          </span>
                        </>
                      )}
                    </div>

                    {/* Severity Pills */}
                    <div className="flex items-center gap-1.5 pt-1">
                      <span className="text-[10px] font-mono text-neutral-500 mr-1">Vulnerabilities:</span>
                      <span className="text-[10px] font-mono font-semibold rounded px-1.5 py-0.2 bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        {sev.critical || 0} Crit
                      </span>
                      <span className="text-[10px] font-mono font-semibold rounded px-1.5 py-0.2 bg-orange-500/20 text-orange-300 border border-orange-500/30">
                        {sev.high || 0} High
                      </span>
                      <span className="text-[10px] font-mono font-semibold rounded px-1.5 py-0.2 bg-amber-500/20 text-amber-300 border border-amber-500/30">
                        {sev.medium || 0} Med
                      </span>
                      <span className="text-[10px] font-mono font-semibold rounded px-1.5 py-0.2 bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                        {sev.low || 0} Low
                      </span>
                      <span className="text-[10px] font-mono font-semibold rounded px-1.5 py-0.2 bg-neutral-900 text-neutral-400 border border-neutral-800">
                        {sev.info || 0} Info
                      </span>
                      <span className="text-[11px] font-mono font-bold text-white ml-1">
                        ({s.findings_count || 0} Total)
                      </span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 self-end lg:self-center shrink-0">
                    <button
                      onClick={() => {
                        onSelectScan(s.scan_id);
                        onNavigateToOverview();
                      }}
                      className="flex items-center gap-1.5 rounded-lg border border-neutral-700 bg-neutral-800 hover:bg-neutral-700 px-3 py-1.5 text-xs font-semibold text-neutral-200 transition-all cursor-pointer shadow-xs"
                      title="Inspect results on Overview dashboard"
                    >
                      <ExternalLink size={13} className="text-purple-400" />
                      <span>Inspect Scan</span>
                    </button>

                    <button
                      onClick={() => onDeleteScan(s.scan_id)}
                      className="flex items-center gap-1 rounded-lg border border-neutral-800 bg-neutral-900/60 hover:bg-rose-500/20 hover:border-rose-500/40 p-2 text-neutral-400 hover:text-rose-300 transition-all cursor-pointer"
                      title="Permanently remove from historical storage"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      )}
    </div>
  );
}
