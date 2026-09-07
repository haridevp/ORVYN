import { useState } from "react";
import type { ScannerFinding, ScannerName } from "../types";
import { SeverityBadge } from "./Badge";
import { ToolMonogram, toolLabel } from "./ToolBadge";
import { SearchX } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export function RawFindingsPanel({ findings }: { findings: ScannerFinding[] }) {
  const tools = Array.from(new Set(findings.map((f) => f.tool)));
  const [active, setActive] = useState<ScannerName | "all">("all");

  const visible = active === "all" ? findings : findings.filter((f) => f.tool === active);

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      className="rounded-2xl border border-[var(--border)] glass-panel p-6 shadow-[var(--shadow-card)]"
    >
      <h2 className="mb-4 text-sm font-bold uppercase tracking-wider text-[var(--text-secondary)]">
        Scanner-wise Results
      </h2>

      <div className="mb-6 flex flex-wrap gap-2 border-b border-gray-700/50 pb-4">
        <button
          onClick={() => setActive("all")}
          className={`relative rounded-lg px-4 py-2 text-sm font-bold uppercase tracking-wider transition-all ${
            active === "all"
              ? "bg-blue-500/20 text-blue-400 border border-blue-500/30"
              : "bg-black/20 text-gray-400 border border-transparent hover:bg-white/5 hover:text-white"
          }`}
        >
          All Scanners
          {active === "all" && (
            <motion.div layoutId="activeTab" className="absolute -bottom-[17px] left-0 right-0 h-[2px] bg-blue-500" />
          )}
        </button>
        {tools.map((tool) => (
          <button
            key={tool}
            onClick={() => setActive(tool)}
            className={`relative flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-bold uppercase tracking-wider transition-all ${
              active === tool
                ? "bg-purple-500/20 text-purple-400 border border-purple-500/30"
                : "bg-black/20 text-gray-400 border border-transparent hover:bg-white/5 hover:text-white"
            }`}
          >
            <ToolMonogram tool={tool} size={16} />
            {toolLabel(tool)}
            {active === tool && (
              <motion.div layoutId="activeTab" className="absolute -bottom-[17px] left-0 right-0 h-[2px] bg-purple-500" />
            )}
          </button>
        ))}
      </div>

      <div className="flex flex-col gap-3">
        <AnimatePresence mode="popLayout">
          {visible.length === 0 && (
            <motion.div 
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="flex flex-col items-center gap-3 py-10 text-center text-sm text-gray-500 bg-white/5 rounded-xl border border-white/5 border-dashed"
            >
              <div className="p-3 bg-black/40 rounded-full border border-white/5">
                <SearchX size={24} className="text-gray-600" />
              </div>
              <p className="font-medium tracking-wide">No findings recorded from this scanner.</p>
            </motion.div>
          )}
          {visible.map((f, i) => (
            <motion.div
              layout
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ delay: i * 0.05 }}
              key={f.id}
              className="rounded-xl border border-gray-700/30 bg-black/20 p-4 transition-all hover:bg-white/5 hover:border-gray-500/50"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <span className="text-sm font-bold text-white tracking-wide">{f.vulnerability}</span>
                <div className="flex items-center gap-3">
                  <ToolMonogram tool={f.tool} size={20} />
                  <SeverityBadge severity={f.severity} />
                </div>
              </div>
              <p className="mt-2 text-sm text-gray-300 leading-relaxed">{f.description}</p>
              {f.evidence && (
                <p className="mt-3 truncate rounded bg-black/60 px-3 py-2 font-mono text-[11px] text-green-400 border border-green-500/10">
                  {f.evidence}
                </p>
              )}
              {f.reference && (
                <p className="mt-3 text-xs font-mono text-blue-400 break-all">
                  Ref: <a href={f.reference} target="_blank" rel="noreferrer" className="underline hover:text-blue-300">{f.reference}</a>
                </p>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
