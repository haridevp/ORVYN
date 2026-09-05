import { useState } from "react";
import type { CorrelatedFinding } from "../types";
import { SEVERITY_STYLE } from "./Badge";

const TOOL_LABEL: Record<string, string> = {
  nuclei: "Nuclei",
  zap: "OWASP ZAP",
  nikto: "Nikto",
};

function ScoreBadge({ finding }: { finding: CorrelatedFinding }) {
  const color = SEVERITY_STYLE[finding.severity].color;
  return (
    <span
      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full border-2 text-xs font-semibold tabular-nums"
      style={{ borderColor: color, color }}
      title={`Confidence ${finding.confidence}%`}
    >
      {finding.confidence}
    </span>
  );
}

function Row({ finding }: { finding: CorrelatedFinding }) {
  const [expanded, setExpanded] = useState(false);
  const isDuplicate = finding.contributing_tools.length > 1;

  return (
    <div className="group rounded-lg border border-transparent hover:border-[var(--border)] hover:bg-[var(--surface-page)]">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-center gap-4 px-3 py-3 text-left"
      >
        <ScoreBadge finding={finding} />

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-medium text-[var(--text-primary)]">
              {finding.vulnerability}
            </span>
            {isDuplicate && (
              <span className="rounded-full bg-[var(--series-blue-wash)] px-2 py-0.5 text-[11px] font-medium text-[var(--series-blue)]">
                {finding.contributing_tools.length}x corroborated
              </span>
            )}
            {finding.conflicting_severity && (
              <span className="rounded-full bg-[var(--status-warning)]/15 px-2 py-0.5 text-[11px] font-medium text-[var(--status-warning)]">
                conflicting severity
              </span>
            )}
          </div>
          <p className="mt-0.5 truncate text-xs text-[var(--text-muted)]">
            {finding.contributing_tools.map((t) => TOOL_LABEL[t] ?? t).join(", ")}
          </p>
        </div>

        <svg
          width="16"
          height="16"
          viewBox="0 0 24 24"
          fill="none"
          className={`shrink-0 text-[var(--text-muted)] transition-transform ${expanded ? "rotate-180" : ""}`}
        >
          <path d="m6 9 6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>

      {expanded && (
        <div className="border-t border-[var(--border)] px-3 py-3 pl-16 text-sm">
          <p className="text-[var(--text-secondary)]">{finding.description}</p>
          {finding.evidence.length > 0 && (
            <div className="mt-2">
              <span className="text-xs font-medium text-[var(--text-muted)]">Scanner evidence</span>
              <ul className="mt-1 flex flex-col gap-1">
                {finding.evidence.map((e, i) => (
                  <li key={i} className="truncate font-mono text-xs text-[var(--text-muted)]">
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {finding.reference && (
            <p className="mt-2 text-xs text-[var(--text-muted)]">Ref: {finding.reference}</p>
          )}
        </div>
      )}
    </div>
  );
}

export function CorrelatedFindingsTable({ findings }: { findings: CorrelatedFinding[] }) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-1)] p-5 shadow-[var(--shadow-card)]">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[var(--text-secondary)]">Consolidated Findings</h2>
        <span className="text-xs text-[var(--text-muted)]">{findings.length} total</span>
      </div>
      <div className="flex flex-col gap-0.5">
        {findings.length === 0 && (
          <p className="px-3 py-6 text-center text-sm text-[var(--text-muted)]">No findings yet.</p>
        )}
        {findings.map((f) => (
          <Row key={f.correlation_id} finding={f} />
        ))}
      </div>
    </div>
  );
}
