import { Crosshair } from "lucide-react";

export function EmptyState() {
  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-slate-800 bg-slate-900/30 px-6 py-16 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-slate-800 border border-slate-700/60 text-slate-400">
        <Crosshair size={22} />
      </div>
      <div className="flex flex-col items-center max-w-md space-y-1">
        <h3 className="text-sm font-semibold tracking-wide text-slate-200">No active targets configured</h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          Specify a target perimeter host above to launch the multi-scanner assessment sequence.
          Findings from Nuclei, OWASP ZAP, and Nikto will correlate in real time.
        </p>
      </div>
    </div>
  );
}
