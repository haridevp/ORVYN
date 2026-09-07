import type { ScannerProgress } from "../types";
import { RunStateBadge } from "./Badge";
import { ToolMonogram, toolLabel } from "./ToolBadge";
import { motion } from "framer-motion";
import { Terminal, ShieldCheck, Activity } from "lucide-react";

interface ScannerProgressListProps {
  scanners: ScannerProgress[];
  onOpenTerminal?: () => void;
  terminalOpen?: boolean;
  logsCount?: number;
}

export function ScannerProgressList({
  scanners,
  onOpenTerminal,
  terminalOpen,
  logsCount = 0,
}: ScannerProgressListProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 }}
      className="rounded-2xl border border-[var(--border)] glass-panel p-6 shadow-[var(--shadow-card)]"
    >
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Activity size={16} className="text-blue-400" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--text-secondary)]">
            Scan Progress & Engine Status
          </h2>
        </div>

        {onOpenTerminal && (
          <button
            onClick={onOpenTerminal}
            className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-semibold tracking-wide transition-all shadow-sm ${
              terminalOpen
                ? "border-cyan-500/50 bg-cyan-500/20 text-cyan-300 shadow-cyan-500/20"
                : "border-gray-700 bg-black/40 text-gray-300 hover:border-cyan-500/40 hover:text-white"
            }`}
          >
            <Terminal size={14} className="text-cyan-400" />
            <span>{terminalOpen ? "Hide Console Output" : "View Live Console"}</span>
            {logsCount > 0 && (
              <span className="rounded-full bg-cyan-950/80 border border-cyan-800/60 px-1.5 py-0.2 text-[10px] font-mono text-cyan-300">
                {logsCount}
              </span>
            )}
          </button>
        )}
      </div>

      <div className="flex flex-col gap-3">
        {scanners.map((s, i) => (
          <motion.div
            key={s.tool}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 + i * 0.1 }}
            className="group relative flex items-center justify-between rounded-xl border border-gray-700/30 bg-black/20 px-4 py-3 transition-all hover:bg-white/5 hover:border-gray-500/50"
          >
            {s.status === "running" && (
              <div className="absolute bottom-0 left-0 h-[2px] bg-blue-500 animate-scan-line w-full rounded-b-xl overflow-hidden opacity-50" />
            )}
            <div className="flex items-center gap-3">
              <ToolMonogram tool={s.tool} />
              <span className="text-sm font-bold text-white tracking-wide">
                {toolLabel(s.tool)}
              </span>

              {s.status === "running" && (
                <span className="flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 px-2 py-0.5 text-[10px] font-semibold tracking-wider text-blue-400 uppercase">
                  <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
                  executing
                </span>
              )}

              {s.status === "completed" && (
                s.simulated ? (
                  <span className="rounded-md border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold tracking-wider text-amber-400 uppercase">
                    simulated
                  </span>
                ) : (
                  <span className="flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold tracking-wider text-emerald-400 uppercase">
                    <ShieldCheck size={11} />
                    real engine
                  </span>
                )
              )}
            </div>
            <div className="flex items-center gap-4">
              {s.status === "completed" && (
                <span className="text-xs font-bold tabular-nums text-gray-300 bg-gray-800/60 border border-gray-700/40 px-2 py-1 rounded-md">
                  {s.findings_count} finding{s.findings_count === 1 ? "" : "s"}
                </span>
              )}
              {s.status === "error" && s.error && (
                <span className="text-xs font-bold text-red-400">{s.error}</span>
              )}
              <RunStateBadge state={s.status} />
            </div>
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}
