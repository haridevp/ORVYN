import type { ScannerProgress } from "../types";
import { RunStateBadge } from "./Badge";
import { ToolMonogram, toolLabel } from "./ToolBadge";

export function ScannerProgressList({ scanners }: { scanners: ScannerProgress[] }) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-1)] p-5 shadow-[var(--shadow-card)]">
      <h2 className="mb-3 text-sm font-semibold text-[var(--text-secondary)]">Scan Progress</h2>
      <div className="flex flex-col gap-0.5">
        {scanners.map((s) => (
          <div
            key={s.tool}
            className="flex items-center justify-between rounded-md px-3 py-2.5 transition-colors hover:bg-[var(--surface-page)]"
          >
            <div className="flex items-center gap-2.5">
              <ToolMonogram tool={s.tool} />
              <span className="text-sm font-medium text-[var(--text-primary)]">
                {toolLabel(s.tool)}
              </span>
              {s.simulated && s.status === "completed" && (
                <span className="text-xs text-[var(--text-muted)]">(simulated)</span>
              )}
            </div>
            <div className="flex items-center gap-3">
              {s.status === "completed" && (
                <span className="text-xs tabular-nums text-[var(--text-muted)]">
                  {s.findings_count} finding{s.findings_count === 1 ? "" : "s"}
                </span>
              )}
              {s.status === "error" && s.error && (
                <span className="text-xs text-[var(--status-critical)]">{s.error}</span>
              )}
              <RunStateBadge state={s.status} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
