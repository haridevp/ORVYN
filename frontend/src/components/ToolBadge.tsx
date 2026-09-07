import type { ScannerName } from "../types";
import { Flame, Zap, Shield, Globe, Network, Lock, Bug } from "lucide-react";

const TOOL: Record<ScannerName, { label: string; icon: React.ReactNode; bg: string; text: string; border: string }> = {
  nuclei: { label: "Nuclei", icon: <Flame size={12} />, bg: "bg-orange-500/20", text: "text-orange-400", border: "border-orange-500/30" },
  zap: { label: "OWASP ZAP", icon: <Zap size={12} />, bg: "bg-blue-500/20", text: "text-blue-400", border: "border-blue-500/30" },
  nikto: { label: "Nikto", icon: <Shield size={12} />, bg: "bg-purple-500/20", text: "text-purple-400", border: "border-purple-500/30" },
  whatweb: { label: "WhatWeb", icon: <Globe size={12} />, bg: "bg-emerald-500/20", text: "text-emerald-400", border: "border-emerald-500/30" },
  nmap: { label: "Nmap NSE", icon: <Network size={12} />, bg: "bg-cyan-500/20", text: "text-cyan-400", border: "border-cyan-500/30" },
  sslyze: { label: "SSLyze", icon: <Lock size={12} />, bg: "bg-rose-500/20", text: "text-rose-400", border: "border-rose-500/30" },
  wapiti: { label: "Wapiti", icon: <Bug size={12} />, bg: "bg-amber-500/20", text: "text-amber-400", border: "border-amber-500/30" },
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
