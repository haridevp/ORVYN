import type { Severity, SeverityDistribution } from "../types";
import { SEVERITY_STYLE } from "./Badge";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

// Part-to-whole data reads best as a stacked bar, not a donut (the dataviz
// skill's form guide reserves pie/donut for nothing here - "Not: a pie of 2
// slices" is its own example of the anti-pattern). A single segmented bar
// gives the same at-a-glance proportion read a donut would, stays legible
// with 5 categories, and every segment ships a direct label below it.
export function SeverityBreakdownCard({ distribution }: { distribution: SeverityDistribution }) {
  const total = ORDER.reduce((sum, s) => sum + distribution[s], 0);

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-1)] p-5 shadow-[var(--shadow-card)]">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[var(--text-secondary)]">Severity Breakdown</h2>
        <p className="text-xs text-[var(--text-muted)]">
          <span className="text-base font-semibold text-[var(--text-primary)]">{total}</span> total
        </p>
      </div>

      <div className="flex h-3 w-full gap-0.5 overflow-hidden rounded-full bg-[var(--gridline)]">
        {ORDER.filter((s) => distribution[s] > 0).map((severity) => (
          <div
            key={severity}
            className="h-full first:rounded-l-full last:rounded-r-full"
            style={{
              width: `${(distribution[severity] / Math.max(total, 1)) * 100}%`,
              backgroundColor: SEVERITY_STYLE[severity].color,
            }}
            title={`${SEVERITY_STYLE[severity].label}: ${distribution[severity]}`}
          />
        ))}
      </div>

      <dl className="mt-4 grid grid-cols-2 gap-y-2.5 gap-x-3">
        {ORDER.map((severity) => {
          const style = SEVERITY_STYLE[severity];
          return (
            <div key={severity} className="flex items-center gap-2 text-sm">
              <span
                aria-hidden="true"
                className="h-2 w-2 shrink-0 rounded-full"
                style={{ backgroundColor: style.color }}
              />
              <dt className="text-[var(--text-secondary)]">{style.label}</dt>
              <dd className="ml-auto font-medium tabular-nums text-[var(--text-primary)]">
                {distribution[severity]}
              </dd>
            </div>
          );
        })}
      </dl>
    </div>
  );
}
