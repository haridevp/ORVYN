import type { ScannerName } from "../types";
import { Flame, Zap, Shield } from "lucide-react";

const TOOL: Record<ScannerName, { label: string; icon: React.ReactNode; bg: string; text: string; border: string }> = {
  nuclei: { label: "Nuclei", icon: <Flame size={12} />, bg: "bg-orange-500/20", text: "text-orange-400", border: "border-orange-500/30" },
  zap: { label: "OWASP ZAP", icon: <Zap size={12} />, bg: "bg-blue-500/20", text: "text-blue-400", border: "border-blue-500/30" },
  nikto: { label: "Nikto", icon: <Shield size={12} />, bg: "bg-purple-500/20", text: "text-purple-400", border: "border-purple-500/30" },
};

export function toolLabel(tool: ScannerName): string {
  return TOOL[tool]?.label ?? tool;
}

export function ToolMonogram({ tool, size = 24 }: { tool: ScannerName; size?: number }) {
  const t = TOOL[tool];
  if (!t) return null;
  return (
    <span
      className={`flex shrink-0 items-center justify-center rounded-full border ${t.border} ${t.bg} ${t.text} shadow-sm backdrop-blur-sm`}
      style={{ width: size, height: size }}
      title={t.label}
    >
      {t.icon}
    </span>
  );
}

export function ToolChip({ tool }: { tool: ScannerName }) {
  const t = TOOL[tool];
  if (!t) return null;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border ${t.border} ${t.bg} px-2 py-0.5 text-xs font-bold ${t.text}`}>
      {t.icon}
      {t.label}
    </span>
  );
}
