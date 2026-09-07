import type { ScannerRunState, Severity } from "../types";

export const SEVERITY_STYLE: Record<Severity, { color: string; bg: string; border: string; label: string }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", label: "Critical" },
  high: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", label: "High" },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", label: "Medium" },
  low: { color: "text-green-400", bg: "bg-green-500/10", border: "border-green-500/30", label: "Low" },
  info: { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", label: "Info" },
};

const RUN_STATE_STYLE: Record<ScannerRunState, { color: string; bg: string; border: string; label: string }> = {
  queued: { color: "text-gray-400", bg: "bg-gray-500/10", border: "border-gray-500/30", label: "Queued" },
  running: { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", label: "Running" },
  completed: { color: "text-green-400", bg: "bg-green-500/10", border: "border-green-500/30", label: "Completed" },
  error: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", label: "Error" },
  cancelled: { color: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/30", label: "Cancelled" },
};

function Dot({ colorClass, spin }: { colorClass: string; spin?: boolean }) {
  // Extract just the color part, e.g., text-red-400 -> bg-red-400
  const bgClass = colorClass.replace('text-', 'bg-');
  return (
    <span className="relative flex h-2 w-2">
      {spin && (
        <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${bgClass} opacity-75`}></span>
      )}
      <span className={`relative inline-flex rounded-full h-2 w-2 ${bgClass}`}></span>
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const style = SEVERITY_STYLE[severity];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border ${style.border} ${style.bg} px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider ${style.color} shadow-sm backdrop-blur-md`}>
      <Dot colorClass={style.color} />
      {style.label}
    </span>
  );
}

export function RunStateBadge({ state }: { state: ScannerRunState }) {
  const style = RUN_STATE_STYLE[state];
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border ${style.border} ${style.bg} px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider ${style.color} shadow-sm backdrop-blur-md`}>
      <Dot colorClass={style.color} spin={state === "running"} />
      {style.label}
    </span>
  );
}
