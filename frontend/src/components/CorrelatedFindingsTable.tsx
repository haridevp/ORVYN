import { useState } from "react";
import type { CorrelatedFinding } from "../types";
import { SeverityBadge } from "./Badge";

const TOOL_LABEL: Record<string, string> = {
  nuclei: "Nuclei",
  zap: "OWASP ZAP",
  nikto: "Nikto",
};

function Row({ finding }: { finding: CorrelatedFinding }) {
  const [expanded, setExpanded] = useState(false);
  const isDuplicate = finding.contributing_tools.length > 1;

  return (
    <div className="rounded-md border border-[var(--border)]">
      <button
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full flex-wrap items-center justify-between gap-2 px-3 py-2.5 text-left"
      >
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium">{finding.vulnerability}</span>
          {isDuplicate && (
            <span
              title={`Reported by ${finding.contributing_tools.length} tools`}
              className="rounded-full bg-[var(--series-blue)]/10 px-2 py-0.5 text-xs font-medium text-[var(--series-blue)]"
            >
              {finding.contributing_tools.length}x corroborated
            </span>
          )}
          {finding.conflicting_severity && (
            <span className="rounded-full bg-[var(--status-warning)]/15 px-2 py-0.5 text-xs font-medium text-[var(--status-warning)]">
              conflicting severity
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-[var(--text-muted)]">
            {finding.contributing_tools.map((t) => TOOL_LABEL[t] ?? t).join(", ")}
          </span>
          <span className="text-xs tabular-nums text-[var(--text-muted)]">
            confidence {finding.confidence}%
          </span>
          <SeverityBadge severity={finding.severity} />
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[var(--border)] px-3 py-3 text-sm">
          <p className="text-[var(--text-secondary)]">{finding.description}</p>
          {finding.evidence.length > 0 && (
            <div className="mt-2">
              <span className="text-xs font-medium text-[var(--text-muted)]">
                Scanner evidence
              </span>
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
    <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-1)] p-5">
      <h2 className="mb-3 text-sm font-semibold text-[var(--text-secondary)]">
        Consolidated Findings
      </h2>
      <div className="flex flex-col gap-2">
        {findings.length === 0 && (
          <p className="text-sm text-[var(--text-muted)]">No findings yet.</p>
        )}
        {findings.map((f) => (
          <Row key={f.correlation_id} finding={f} />
        ))}
      </div>
    </div>
  );
}
