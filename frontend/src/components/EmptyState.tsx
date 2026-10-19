import { Crosshair } from "lucide-react";

export function EmptyState() {
  return (
    <div className="flex flex-col items-center gap-3 rounded-2xl border border-dashed border-neutral-800 bg-[#0a0b10] px-6 py-16 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-neutral-900 border border-neutral-800 text-neutral-400">
        <Crosshair size={22} />
      </div>
      <div className="flex flex-col items-center max-w-md space-y-1">
        <h3 className="text-sm font-semibold tracking-wide text-neutral-200">No active targets configured</h3>
        <p className="text-xs text-neutral-400 leading-relaxed">
          Specify a target perimeter host to launch the multi-scanner assessment sequence.
          Findings from all security engines will correlate in real time with judicial RAG validation.
        </p>
      </div>
    </div>
  );
}
