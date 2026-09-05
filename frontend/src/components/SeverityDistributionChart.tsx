import type { Severity, SeverityDistribution } from "../types";
import { SEVERITY_STYLE } from "./Badge";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

// Horizontal bars with the count directly labeled on every row - a single
// "count" series doesn't need a separate legend box since each row already
// names its own severity (per the dataviz skill's direct-label rule).
export function SeverityDistributionChart({ distribution }: { distribution: SeverityDistribution }) {
  const max = Math.max(1, ...ORDER.map((s) => distribution[s]));

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-1)] p-5">
      <h2 className="mb-3 text-sm font-semibold text-[var(--text-secondary)]">
        Severity Distribution
      </h2>
      <div className="flex flex-col gap-2">
        {ORDER.map((severity) => {
          const count = distribution[severity];
          const widthPct = (count / max) * 100;
          const style = SEVERITY_STYLE[severity];
          return (
            <div key={severity} className="flex items-center gap-3">
              <span className="w-16 shrink-0 text-xs font-medium text-[var(--text-secondary)]">
                {style.label}
              </span>
              <div className="h-3 flex-1 overflow-hidden rounded-full bg-[var(--gridline)]">
                <div
                  className="h-full rounded-full transition-all"
                  style={{ width: `${count > 0 ? Math.max(widthPct, 4) : 0}%`, backgroundColor: style.color }}
                />
              </div>
              <span className="w-6 shrink-0 text-right text-xs tabular-nums text-[var(--text-primary)]">
                {count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
