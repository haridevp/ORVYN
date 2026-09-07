import { ShieldCheck, Clock, Zap, Flame, CheckCircle, TrendingUp, Shield } from "lucide-react";
import type { SeverityDistribution } from "../types";

interface ExecutiveMetricsProps {
  distribution: SeverityDistribution;
  totalFindings: number;
  duplicateGroups: number;
  isScanning: boolean;
  enginesCount?: number;
  engineNames?: string;
}

export function ExecutiveMetrics({
  distribution,
  totalFindings,
  duplicateGroups,
  isScanning,
  enginesCount = 7,
  engineNames = "Nuclei • ZAP • Nikto • WhatWeb • Nmap • SSLyze • Wapiti",
}: ExecutiveMetricsProps) {
  const critical = distribution.critical || 0;
  const high = distribution.high || 0;
  const medium = distribution.medium || 0;
  const low = distribution.low || 0;
  const total = totalFindings;

  // Calculate SVG donut stroke offsets only if total > 0
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const hasThreats = total > 0;

  const critPct = hasThreats ? critical / total : 0;
  const highPct = hasThreats ? high / total : 0;
  const medPct = hasThreats ? medium / total : 0;
  const lowPct = hasThreats ? low / total : 0;

  const critDash = critPct * circumference;
  const highDash = highPct * circumference;
  const medDash = medPct * circumference;
  const lowDash = lowPct * circumference;

  const hoursSaved = hasThreats ? Math.round(total * 1.8) : 0;
  const engineerDays = hasThreats ? (hoursSaved / 8).toFixed(1) : "0";

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {/* 1. Total Threats & Critical Card */}
      <div
        className={`enterprise-panel p-4 space-y-3 transition-colors ${
          hasThreats ? "border-rose-500/30" : "border-slate-800"
        }`}
      >
        <div className="flex items-center justify-between">
          <div>
            <div className={`flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider ${hasThreats ? "text-rose-400" : "text-emerald-400"}`}>
              {hasThreats ? <Flame size={14} /> : <Shield size={14} />}
              <span>{hasThreats ? "Threats Flagged" : "Threat Posture"}</span>
            </div>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-2xl font-bold tracking-tight text-white font-mono">
                {totalFindings}
              </span>
              <span className="text-[11px] text-slate-400">
                {hasThreats ? `${duplicateGroups} groups` : "Zero exploits"}
              </span>
            </div>
          </div>

          {/* Mini Donut Chart */}
          <div className="relative h-12 w-12 shrink-0">
            <svg className="h-full w-full -rotate-90 transform" viewBox="0 0 76 76">
              <circle
                cx="38"
                cy="38"
                r={radius}
                className={hasThreats ? "stroke-slate-800" : "stroke-emerald-950"}
                strokeWidth="7"
                fill="transparent"
              />
              {hasThreats ? (
                <>
                  <circle
                    cx="38"
                    cy="38"
                    r={radius}
                    stroke="#ef4444"
                    strokeWidth="7"
                    strokeDasharray={`${critDash} ${circumference}`}
                    fill="transparent"
                  />
                  <circle
                    cx="38"
                    cy="38"
                    r={radius}
                    stroke="#f97316"
                    strokeWidth="7"
                    strokeDasharray={`${highDash} ${circumference}`}
                    strokeDashoffset={-critDash}
                    fill="transparent"
                  />
                  <circle
                    cx="38"
                    cy="38"
                    r={radius}
                    stroke="#eab308"
                    strokeWidth="7"
                    strokeDasharray={`${medDash} ${circumference}`}
                    strokeDashoffset={-(critDash + highDash)}
                    fill="transparent"
                  />
                  <circle
                    cx="38"
                    cy="38"
                    r={radius}
                    stroke="#06b6d4"
                    strokeWidth="7"
                    strokeDasharray={`${lowDash} ${circumference}`}
                    strokeDashoffset={-(critDash + highDash + medDash)}
                    fill="transparent"
                  />
                </>
              ) : (
                <circle
                  cx="38"
                  cy="38"
                  r={radius}
                  className="stroke-emerald-500"
                  strokeWidth="7"
                  strokeDasharray={`${circumference} ${circumference}`}
                  fill="transparent"
                />
              )}
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className={`text-[10px] font-bold ${hasThreats ? "text-rose-400" : "text-emerald-400 font-mono"}`}>
                {hasThreats ? `${critical}C` : "OK"}
              </span>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-slate-800/80 pt-2.5 text-[11px] font-mono">
          <span className="text-slate-400">Surface Severity</span>
          <span className="flex items-center gap-1.5 font-medium">
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                critical > 0
                  ? "bg-rose-500"
                  : high > 0
                  ? "bg-orange-500"
                  : medium > 0
                  ? "bg-amber-500"
                  : "bg-emerald-500"
              }`}
            />
            <span
              className={
                critical > 0
                  ? "text-rose-400"
                  : high > 0
                  ? "text-orange-400"
                  : medium > 0
                  ? "text-amber-400"
                  : "text-emerald-400"
              }
            >
              {critical > 0
                ? "Critical Exposure"
                : high > 0
                ? "High Exposure"
                : medium > 0
                ? "Elevated Risk"
                : "All perimeters verified clean"}
            </span>
          </span>
        </div>
      </div>

      {/* 2. Automated Triage & Deduplication */}
      <div className="enterprise-panel p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-emerald-400">
              <ShieldCheck size={14} />
              <span>Automated Triage</span>
            </div>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-2xl font-bold tracking-tight text-white font-mono">
                {duplicateGroups}
              </span>
              <span className="text-[11px] text-slate-400">Correlated Vectors</span>
            </div>
          </div>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <CheckCircle size={18} />
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-slate-800/80 pt-2.5 text-[11px] text-slate-400 font-mono">
          <span>Deduplication</span>
          <span className="text-emerald-400 font-medium">
            {isScanning ? "Correlating Live..." : (hasThreats ? "Cross-Engine Linked" : "Standby")}
          </span>
        </div>
      </div>

      {/* 3. Audit Time Saved */}
      <div className="enterprise-panel p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-blue-400">
              <Clock size={14} />
              <span>Audit Time Saved</span>
            </div>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-2xl font-bold tracking-tight text-white font-mono">
                {hoursSaved}h
              </span>
              <span className="text-[11px] text-slate-400">~{engineerDays}d manual</span>
            </div>
          </div>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <TrendingUp size={18} />
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-slate-800/80 pt-2.5 text-[11px] text-slate-400 font-mono">
          <span>Execution Velocity</span>
          <span className="text-blue-400 font-medium">Parallel DAST</span>
        </div>
      </div>

      {/* 4. Multi-Scanner Cluster */}
      <div className="enterprise-panel p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-300">
              <Zap size={14} className="text-blue-400" />
              <span>Active Engines</span>
            </div>
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-2xl font-bold tracking-tight text-white font-mono">
                {enginesCount} Scanners
              </span>
              <span className="text-[11px] text-slate-400 truncate max-w-[170px]" title={engineNames}>
                {engineNames}
              </span>
            </div>
          </div>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-800 border border-slate-700 text-slate-300">
            <Zap size={18} />
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-slate-800/80 pt-2.5 text-[11px] font-mono">
          <span className="text-slate-400">Cluster Status</span>
          <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
            <span className={`h-1.5 w-1.5 rounded-full ${isScanning ? "bg-blue-400 animate-ping" : "bg-emerald-400"}`} />
            {isScanning ? "Scanning Live" : "Cluster Ready"}
          </span>
        </div>
      </div>
    </div>
  );
}
