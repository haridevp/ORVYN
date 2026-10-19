import type { ScannerFinding } from "../types";
import { SeverityBadge } from "./Badge";
import { ToolMonogram, toolLabel } from "./ToolBadge";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldAlert } from "lucide-react";

interface LiveFindingsFeedProps {
  findings: ScannerFinding[];
  isScanning: boolean;
  onSelectFinding?: (finding: ScannerFinding) => void;
}

export function LiveFindingsFeed({
  findings,
  isScanning,
  onSelectFinding,
}: LiveFindingsFeedProps) {
  if (findings.length === 0) {
    return (
      <div className="enterprise-panel p-5 text-center">
        <div className="flex flex-col items-center justify-center py-6 text-neutral-500">
          <ShieldAlert size={28} className="text-neutral-600 mb-2 opacity-60" />
          <p className="text-xs font-semibold uppercase tracking-wider text-neutral-400">
            {isScanning ? "Active Scanning in Progress..." : "No Vulnerabilities Detected"}
          </p>
          <p className="text-xs text-neutral-500 mt-1 max-w-sm">
            {isScanning
              ? "Security engines are dispatching probes. Live findings will stream into this feed the instant they are uncovered."
              : "No in-scope security vulnerabilities or threat signatures matched during assessment."}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="enterprise-panel p-5">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-6 w-6 items-center justify-center rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldAlert size={14} />
          </div>
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-neutral-300">
              Live Threat Stream
            </h3>
            <span className="text-[11px] text-neutral-500">
              {findings.length} real-time finding{findings.length === 1 ? "" : "s"} intercepted
            </span>
          </div>
        </div>

        {isScanning && (
          <span className="flex items-center gap-1.5 rounded-full border border-purple-500/30 bg-purple-500/10 px-2.5 py-0.5 text-[11px] font-medium text-purple-400">
            <span className="h-1.5 w-1.5 rounded-full bg-purple-400 animate-pulse" />
            Live Ingestion Active
          </span>
        )}
      </div>

      <div className="flex flex-col gap-2.5 max-h-[380px] overflow-y-auto pr-1">
        <AnimatePresence initial={false}>
          {findings.map((f, index) => (
            <motion.div
              key={f.id || `${f.tool}-${f.vulnerability}-${index}`}
              initial={{ opacity: 0, y: -8, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.2 }}
              onClick={() => onSelectFinding?.(f)}
              className="group flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-lg border border-neutral-800 bg-[#0e0f14] p-3 hover:border-neutral-700 hover:bg-neutral-900/60 transition-all cursor-pointer"
            >
              <div className="flex items-start sm:items-center gap-3 min-w-0">
                <SeverityBadge severity={f.severity} />
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-neutral-200 truncate group-hover:text-purple-300 transition-colors">
                      {f.vulnerability}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-0.5 text-[11px] text-neutral-500 font-mono truncate">
                    <span className="truncate max-w-md">{f.evidence || f.target}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between sm:justify-end gap-2.5 shrink-0 border-t sm:border-t-0 border-neutral-800/50 pt-2 sm:pt-0">
                <div className="flex items-center gap-1.5 text-[11px] font-mono text-neutral-400">
                  <ToolMonogram tool={f.tool} />
                  <span className="text-neutral-400 text-xs">{toolLabel(f.tool)}</span>
                </div>

                {f.reference && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-neutral-800 text-neutral-400 border border-neutral-700/50">
                    CWE Ref
                  </span>
                )}
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}
