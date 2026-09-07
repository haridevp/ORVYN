import type { Severity, SeverityDistribution } from "../types";
import { SEVERITY_STYLE } from "./Badge";
import { motion } from "framer-motion";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function SeverityBreakdownCard({ distribution }: { distribution: SeverityDistribution }) {
  const total = ORDER.reduce((sum, s) => sum + distribution[s], 0);

  return (
    <motion.div 
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="rounded-2xl border border-[var(--border)] glass-panel p-6 shadow-[var(--shadow-card)]"
    >
      <div className="mb-6 flex items-center justify-between">
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--text-secondary)]">Severity Breakdown</h2>
        <p className="text-xs text-[var(--text-muted)]">
          <span className="text-xl font-black text-white">{total}</span> total
        </p>
      </div>

      <div className="relative flex h-4 w-full gap-[2px] overflow-hidden rounded-full bg-black/50 shadow-inner">
        {ORDER.filter((s) => distribution[s] > 0).map((severity, index) => {
          const style = SEVERITY_STYLE[severity];
          const widthPercent = (distribution[severity] / Math.max(total, 1)) * 100;
          return (
            <motion.div
              key={severity}
              initial={{ width: 0 }}
              animate={{ width: `${widthPercent}%` }}
              transition={{ duration: 0.8, delay: index * 0.1, ease: "easeOut" }}
              className={`h-full ${style.bg.replace('bg-', 'bg-').replace('/10', '/60')} shadow-[0_0_10px_currentColor]`}
              style={{ color: style.color.replace('text-', '') }}
              title={`${style.label}: ${distribution[severity]}`}
            />
          );
        })}
      </div>

      <dl className="mt-8 grid grid-cols-2 gap-y-4 gap-x-4">
        {ORDER.map((severity, i) => {
          const style = SEVERITY_STYLE[severity];
          return (
            <motion.div 
              key={severity} 
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.3 + i * 0.1 }}
              className="flex flex-col gap-1 rounded-xl bg-white/5 p-3 border border-white/5"
            >
              <div className="flex items-center gap-2 text-xs">
                <span
                  aria-hidden="true"
                  className={`h-2.5 w-2.5 shrink-0 rounded-full ${style.bg.replace('/10', '/60')} shadow-sm`}
                />
                <dt className="text-gray-400 font-bold uppercase tracking-wide">{style.label}</dt>
              </div>
              <dd className={`font-black tabular-nums text-2xl ${style.color}`}>
                {distribution[severity]}
              </dd>
            </motion.div>
          );
        })}
      </dl>
    </motion.div>
  );
}
