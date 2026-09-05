import { useState } from "react";
import type { ScannerFinding, ScannerName } from "../types";
import { SeverityBadge } from "./Badge";

const TOOL_LABEL: Record<string, string> = {
  nuclei: "Nuclei",
  zap: "OWASP ZAP",
  nikto: "Nikto",
};

export function RawFindingsPanel({ findings }: { findings: ScannerFinding[] }) {
  const tools = Array.from(new Set(findings.map((f) => f.tool)));
  const [active, setActive] = useState<ScannerName | "all">("all");

  const visible = active === "all" ? findings : findings.filter((f) => f.tool === active);

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-1)] p-5 shadow-[var(--shadow-card)]">
      <h2 className="mb-3 text-sm font-semibold text-[var(--text-secondary)]">
        Scanner-wise Results
      </h2>

      <div className="mb-4 flex gap-1 border-b border-[var(--border)]">
        {(["all", ...tools] as (ScannerName | "all")[]).map((tool) => (
          <button
            key={tool}
            onClick={() => setActive(tool)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
              active === tool
                ? "border-[var(--series-blue)] text-[var(--text-primary)]"
                : "border-transparent text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
            }`}
          >
            {tool === "all" ? "All" : TOOL_LABEL[tool] ?? tool}
          </button>
        ))}
      </div>

      <div className="flex flex-col gap-2">
        {visible.length === 0 && (
          <p className="px-1 py-6 text-center text-sm text-[var(--text-muted)]">
            No findings from this scanner.
          </p>
        )}
        {visible.map((f) => (
          <div
            key={f.id}
            className="rounded-md border border-[var(--border)] p-3.5 transition-colors hover:bg-[var(--surface-page)]"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-sm font-medium text-[var(--text-primary)]">{f.vulnerability}</span>
              <div className="flex items-center gap-2">
                <span className="text-xs uppercase tracking-wide text-[var(--text-muted)]">
                  {TOOL_LABEL[f.tool] ?? f.tool}
                </span>
                <SeverityBadge severity={f.severity} />
              </div>
            </div>
            <p className="mt-1.5 text-sm text-[var(--text-secondary)]">{f.description}</p>
            {f.evidence && (
              <p className="mt-1.5 truncate rounded bg-[var(--surface-page)] px-2 py-1 font-mono text-xs text-[var(--text-muted)]">
                {f.evidence}
              </p>
            )}
            {f.reference && (
              <p className="mt-1.5 text-xs text-[var(--text-muted)]">Ref: {f.reference}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
