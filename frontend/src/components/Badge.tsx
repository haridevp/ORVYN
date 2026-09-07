import type { ScannerRunState, Severity } from "../types";

// Severity is ordinal/state-like, so it reuses the reserved status palette
// (good/warning/serious/critical) rather than a categorical hue - info gets
// a neutral gray since it isn't a "bad" state. Color is never the only
// signal: every badge pairs a dot with a text label.
const SEVERITY_STYLE: Record<Severity, { color: string; label: string }> = {
  critical: { color: "var(--status-critical)", label: "Critical" },
  high: { color: "var(--status-serious)", label: "High" },
  medium: { color: "var(--status-warning)", label: "Medium" },
  low: { color: "var(--status-good)", label: "Low" },
  info: { color: "var(--status-neutral)", label: "Info" },
};

const RUN_STATE_STYLE: Record<ScannerRunState, { color: string; label: string }> = {
  queued: { color: "var(--status-neutral)", label: "Queued" },
  running: { color: "var(--series-blue)", label: "Running" },
  completed: { color: "var(--status-good)", label: "Completed" },
  error: { color: "var(--status-critical)", label: "Error" },
};

function Dot({ color, spin }: { color: string; spin?: boolean }) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block h-2 w-2 rounded-full ${spin ? "animate-pulse" : ""}`}
      style={{ backgroundColor: color }}
    />
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const style = SEVERITY_STYLE[severity];
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--border)] px-2.5 py-1 text-xs font-medium text-[var(--text-primary)]">
      <Dot color={style.color} />
      {style.label}
    </span>
  );
}

export function RunStateBadge({ state }: { state: ScannerRunState }) {
  const style = RUN_STATE_STYLE[state];
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--border)] px-2.5 py-1 text-xs font-medium text-[var(--text-primary)]">
      <Dot color={style.color} spin={state === "running"} />
      {style.label}
    </span>
  );
}

export { SEVERITY_STYLE };
