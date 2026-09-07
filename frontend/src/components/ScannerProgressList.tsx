import type { ScannerProgress } from "../types";
import { RunStateBadge } from "./Badge";
import { ToolMonogram, toolLabel } from "./ToolBadge";
import { motion } from "framer-motion";
import { Terminal, ShieldCheck, Activity, Clock, Hourglass, CheckCircle2, StopCircle, XCircle } from "lucide-react";

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
}: ScannerProgressListProps) {
  const isCompleted = overallStatus === "completed";
  const isCancelled = overallStatus === "cancelled";
  const isFinished = isCompleted || isCancelled;
  const pct = isFinished ? 100 : Math.max(0, Math.min(100, progressPct));

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="enterprise-panel p-5 space-y-4"
    >
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <div className="flex h-6 w-6 items-center justify-center rounded-md bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Activity size={14} />
          </div>
          <div>
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Execution Telemetry & Engines
            </h2>
            <span className="text-[11px] text-slate-500">
              {scanners.filter((s) => s.status === "completed").length} of {scanners.length} engines completed
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {!isFinished && onCancelScan && (
            <button
              onClick={onCancelScan}
              className="flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 hover:bg-rose-500/20 px-3 py-1.5 text-xs font-medium text-rose-300 transition-all cursor-pointer"
              title="Abort and end current scan execution"
            >
              <StopCircle size={13} className="text-rose-400" />
              <span>Abort Scan</span>
            </button>
          )}

          {onOpenTerminal && (
            <button
              onClick={onOpenTerminal}
              className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition-all ${
                terminalOpen
                  ? "border-blue-500/40 bg-blue-500/15 text-blue-300"
                  : "border-slate-800 bg-slate-900/80 text-slate-400 hover:border-slate-700 hover:text-slate-200"
              }`}
            >
              <Terminal size={13} className="text-blue-400" />
              <span>{terminalOpen ? "Hide Console" : "Live Console"}</span>
              {logsCount > 0 && (
                <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[10px] font-mono text-slate-400">
                  {logsCount}
                </span>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Progress & ETA Telemetry Bar */}
      <div className="rounded-lg border border-slate-800/80 bg-slate-900/50 p-3.5 space-y-2.5">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-200 font-mono">{pct}%</span>
            <span className="text-slate-500">•</span>
            <span className="text-slate-400">
              {isCompleted ? (
                <span className="text-emerald-400 font-medium flex items-center gap-1">
                  <CheckCircle2 size={13} /> Assessment Completed
                </span>
              ) : isCancelled ? (
                <span className="text-rose-400 font-medium flex items-center gap-1">
                  <XCircle size={13} /> Scan Aborted by User
                </span>
              ) : (
                "Scanning & Correlating..."
              )}
            </span>
          </div>

          <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400">
            <div className="flex items-center gap-1.5" title="Elapsed assessment runtime">
              <Clock size={12} className="text-slate-500" />
              <span>Elapsed: {formatSeconds(elapsedSeconds)}</span>
            </div>

            {!isFinished && etaSeconds !== undefined && etaSeconds !== null && (
              <div className="flex items-center gap-1.5 text-blue-400" title="Estimated time to complete scan">
                <Hourglass size={12} className="text-blue-400" />
                <span>ETA: {formatEta(etaSeconds)}</span>
              </div>
            )}
          </div>
        </div>

        {/* The Bar */}
        <div className="relative h-2 w-full overflow-hidden rounded-full bg-slate-800/80">
          <motion.div
            className={`h-full rounded-full ${
              isCompleted
                ? "bg-emerald-500"
                : "bg-blue-500"
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

      {/* Engine Status Rows */}
      <div className="flex flex-col gap-2">
        {scanners.map((s) => (
          <div
            key={s.tool}
            className="flex items-center justify-between rounded-lg border border-slate-800/60 bg-slate-900/40 px-3.5 py-2.5 hover:border-slate-700/80 transition-all"
          >
            <div className="flex items-center gap-3">
              <ToolMonogram tool={s.tool} />
              <span className="text-xs font-semibold text-slate-200">
                {toolLabel(s.tool)}
              </span>

              {s.status === "running" && (
                <span className="flex items-center gap-1 rounded border border-blue-500/20 bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-400">
                  <span className="h-1 w-1 rounded-full bg-blue-400 animate-pulse" />
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
                    : "bg-slate-800/80 text-slate-400 border-slate-700/50"
                }`}>
                  {s.findings_count} finding{s.findings_count === 1 ? "" : "s"}
                </span>
              )}
              {s.status === "error" && s.error && (
                <span className="text-xs text-rose-400 truncate max-w-xs">{s.error}</span>
              )}
              <RunStateBadge state={s.status} />
            </div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
