import type { ScannerName } from "../types";

const TOOL: Record<ScannerName, { label: string; initial: string; color: string }> = {
  nuclei: { label: "Nuclei", initial: "N", color: "var(--tool-nuclei)" },
  zap: { label: "OWASP ZAP", initial: "Z", color: "var(--tool-zap)" },
  nikto: { label: "Nikto", initial: "K", color: "var(--tool-nikto)" },
};

export function toolLabel(tool: ScannerName): string {
  return TOOL[tool]?.label ?? tool;
}

export function ToolMonogram({ tool, size = 20 }: { tool: ScannerName; size?: number }) {
  const t = TOOL[tool];
  if (!t) return null;
  return (
    <span
      className="flex shrink-0 items-center justify-center rounded-full text-[10px] font-bold text-white"
      style={{ width: size, height: size, backgroundColor: t.color }}
      title={t.label}
    >
      {t.initial}
    </span>
  );
}

export function ToolChip({ tool }: { tool: ScannerName }) {
  const t = TOOL[tool];
  if (!t) return null;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[var(--text-secondary)]">
      <ToolMonogram tool={tool} size={14} />
      {t.label}
    </span>
  );
}
