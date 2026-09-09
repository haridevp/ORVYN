import { useState, useEffect, useMemo } from "react";
import type { EnvironmentInfo, ScannerName, TargetProbeResponse } from "../types";
import { getEnvironment, probeTarget } from "../api";
import {
  Play,
  Zap,
  Shield,
  Search,
  Radio,
  CheckCircle2,
  AlertCircle,
  Activity,
  X,
  Sliders,
  ChevronDown,
  ChevronUp,
  Globe,
  Network,
  Lock,
  Bug,
  Database,
  Cpu,
  Sparkles,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const ALL_SCANNERS: { id: ScannerName; label: string; icon: React.ReactNode }[] = [
  { id: "nuclei", label: "Nuclei (Templates)", icon: <FlameIcon size={14} /> },
  { id: "zap", label: "OWASP ZAP (DAST)", icon: <Zap size={14} /> },
  { id: "nikto", label: "Nikto (Web Server)", icon: <Shield size={14} /> },
  { id: "whatweb", label: "WhatWeb (Tech Stack)", icon: <Globe size={14} /> },
  { id: "nmap", label: "Nmap NSE (Port/CVE)", icon: <Network size={14} /> },
  { id: "sslyze", label: "SSLyze (TLS/SSL)", icon: <Lock size={14} /> },
  { id: "wapiti", label: "Wapiti (Web Vulns)", icon: <Bug size={14} /> },
  { id: "sqlmap", label: "SQLMap (SQL Injection)", icon: <Database size={14} /> },
  { id: "ffuf", label: "FFUF (Fuzzing / Discovery)", icon: <Search size={14} /> },
];

function FlameIcon({ size = 14 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z" />
    </svg>
  );
}

function extractDomain(urlOrHost: string): string {
  try {
    const raw = urlOrHost.trim().replace(/^https?:\/\//i, "").split("/")[0].split(":")[0];
    return raw || "target.com";
  } catch {
    return "target.com";
  }
}

interface Props {
  onStart: (
    target: string,
    scanners: ScannerName[],
    profile: string,
    inScope?: string[],
    outOfScope?: string[],
    template?: string | null,
  ) => void;
  disabled: boolean;
}

export function ScanForm({ onStart, disabled }: Props) {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("web");
  const [scanners, setScanners] = useState<ScannerName[]>([
    "whatweb",
    "nuclei",
    "nikto",
    "zap",
    "wapiti",
    "sslyze",
  ]);

  // Environment State
  const [environment, setEnvironment] = useState<EnvironmentInfo | null>(null);

  // Scope & Perimeter Management state (default: strict host scope)
  const [scopeMode, setScopeMode] = useState<"wildcard" | "strict" | "custom">("strict");
  const [showScopePanel, setShowScopePanel] = useState(false);
  const [customInScope, setCustomInScope] = useState<string[]>([]);
  const [customInInput, setCustomInInput] = useState("");
  const [outOfScope, setOutOfScope] = useState<string[]>(["logout", "auth.*"]);
  const [outOfScopeInput, setOutOfScopeInput] = useState("");

  // Live pre-flight probe state
  const [isProbing, setIsProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<TargetProbeResponse | null>(null);

  const activeDomain = useMemo(() => extractDomain(target || "target.com"), [target]);

  // Fetch environment from backend
  useEffect(() => {
    getEnvironment()
      .then(setEnvironment)
      .catch(() => {});
  }, []);

  // Debounced alive probe
  useEffect(() => {
    const trimmed = target.trim();
    if (!trimmed || trimmed.length < 3) {
      setProbeResult(null);
      setIsProbing(false);
      return;
    }

    const timer = setTimeout(async () => {
      setIsProbing(true);
      try {
        const res = await probeTarget(trimmed);
        setProbeResult(res);
      } catch {
        // Silent catch for probe
      } finally {
        setIsProbing(false);
      }
    }, 600);

    return () => clearTimeout(timer);
  }, [target]);

  function toggleScanner(id: ScannerName) {
    setScanners((prev) => (prev.includes(id) ? prev.filter((s) => s !== id) : [...prev, id]));
  }

  function handleAddInScope() {
    const val = customInInput.trim();
    if (val && !customInScope.includes(val)) {
      setCustomInScope([...customInScope, val]);
      setCustomInInput("");
    }
  }

  function handleRemoveInScope(val: string) {
    setCustomInScope(customInScope.filter((item) => item !== val));
  }

  function handleAddOutOfScope(valToAdd?: string) {
    const val = (valToAdd || outOfScopeInput).trim();
    if (val && !outOfScope.includes(val)) {
      setOutOfScope([...outOfScope, val]);
      if (!valToAdd) setOutOfScopeInput("");
    }
  }

  function handleRemoveOutOfScope(val: string) {
    setOutOfScope(outOfScope.filter((item) => item !== val));
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!target.trim() || scanners.length === 0) return;

    let effectiveInScope: string[];
    if (scopeMode === "wildcard") {
      effectiveInScope = [`*.${activeDomain}`, activeDomain];
    } else if (scopeMode === "strict") {
      effectiveInScope = [activeDomain];
    } else {
      effectiveInScope = customInScope.length > 0 ? customInScope : [`*.${activeDomain}`, activeDomain];
    }

    onStart(
      target.trim(),
      scanners,
      profile,
      effectiveInScope,
      outOfScope,
      "auto"
    );
  }

  function applySuggestion(suggested: string) {
    setTarget(suggested);
  }

  return (
    <div className="enterprise-panel p-5 space-y-4">
      {/* Top Bar: Environment Mode & HexStrike MCP Status */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-slate-800/80 text-xs">
        <div className="flex items-center gap-2">
          <div className="flex h-5 w-5 items-center justify-center rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Cpu size={12} />
          </div>
          <span className="font-semibold text-slate-200">Execution Engine:</span>
          {environment?.is_kali ? (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-0.5 text-[11px] font-mono text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Kali Linux Native Host Tools
            </span>
          ) : environment?.is_parrot ? (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-0.5 text-[11px] font-mono text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Parrot Security OS Native Host
            </span>
          ) : environment?.docker_available ? (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-blue-500/15 border border-blue-500/30 px-2.5 py-0.5 text-[11px] font-mono text-blue-300">
              <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
              Curated HexStrike MCP Container Mode
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 border border-amber-500/30 px-2.5 py-0.5 text-[11px] font-mono text-amber-300">
              <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
              Simulated Security Telemetry Mode
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono">
          <span>Host: <strong className="text-slate-300">{environment?.os_name || "Linux Host"}</strong></span>
        </div>
      </div>

      {/* Autonomous AI Orchestration Banner */}
      <div className="rounded-xl border border-purple-500/40 bg-gradient-to-r from-purple-950/30 via-slate-900/90 to-blue-950/30 p-3.5 shadow-lg shadow-purple-500/5 ring-1 ring-purple-500/20">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-purple-600/30 border border-purple-400 text-purple-200 shadow-md shadow-purple-500/20">
              <Sparkles size={18} className="animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-slate-100 text-xs tracking-wide">🤖 ORVYN Autonomous AI Orchestrator</span>
                <span className="rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-semibold flex items-center gap-1">
                  <CheckCircle2 size={11} /> Auto-Targeting Active
                </span>
              </div>
              <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">
                Backend LLM autonomously inspects perimeter recon (WhatWeb tech stack, Nmap service ports, HTTP banners) and dynamically selects the optimal vulnerability attack chain from 30 backend templates (5–9 tools per chain).
              </p>
            </div>
          </div>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4 pt-2 border-t border-slate-800/60">
        {/* Main Controls Row */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
          {/* Target Host Input */}
          <div className="md:col-span-5 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <label className="font-semibold text-slate-300 flex items-center gap-1.5">
                <Search size={13} className="text-slate-400" />
                Target Perimeter Host / URL
              </label>
              {isProbing && (
                <span className="flex items-center gap-1 text-[11px] font-mono text-blue-400">
                  <Radio size={11} className="animate-spin" />
                  Probing...
                </span>
              )}
            </div>

            <div className="relative">
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. scanme.nmap.org or target.com"
                className="w-full rounded-lg border border-slate-700/80 bg-slate-900/90 px-3.5 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-500 outline-none transition-all focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30"
                minLength={3}
                required
              />
            </div>
          </div>

          {/* Scan Profile Selector */}
          <div className="md:col-span-3 space-y-1.5">
            <label className="block text-xs font-semibold text-slate-300">
              Intensity Profile
            </label>
            <div className="relative">
              <select
                value={profile}
                onChange={(e) => setProfile(e.target.value)}
                className="w-full rounded-lg border border-slate-700/80 bg-slate-900/90 px-3 py-2 text-xs text-slate-200 outline-none transition-all focus:border-blue-500 cursor-pointer appearance-none pr-8"
              >
                <option value="recon">Reconnaissance (~20s quick probe)</option>
                <option value="web">Web Application (~45-60s standard)</option>
                <option value="full">Comprehensive Full (~2 mins)</option>
                <option value="deep">Deep Multi-Tool Audit (~5–10 mins)</option>
                <option value="unlimited">Exhaustive Enterprise (No Timeout)</option>
              </select>
              <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2.5 text-slate-400">
                <ChevronDown size={14} />
              </div>
            </div>
          </div>

          {/* Launch Button */}
          <div className="md:col-span-4 flex items-end">
            <button
              type="submit"
              disabled={disabled || scanners.length === 0}
              className={`w-full flex h-[38px] items-center justify-center gap-2 rounded-lg px-4 text-xs font-medium transition-all ${
                disabled || scanners.length === 0
                  ? "bg-slate-800 text-slate-500 border border-slate-700/50 cursor-not-allowed"
                  : "bg-blue-600 hover:bg-blue-500 text-white shadow-sm border border-blue-500/40 cursor-pointer active:scale-[0.99]"
              }`}
            >
              {disabled ? (
                <>
                  <Activity size={14} className="animate-spin text-blue-300" />
                  <span>Assessment In Progress...</span>
                </>
              ) : (
                <>
                  <Play size={13} fill="currentColor" />
                  <span>Launch Template Assessment</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Engine Checkbox Pills */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/60">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mr-1">
              Engines ({scanners.length}/7):
            </span>
            <div className="flex items-center gap-1 mr-2 bg-slate-950/80 p-0.5 rounded border border-slate-800 text-[10px] font-mono">
              <button
                type="button"
                onClick={() => setScanners(["nuclei", "zap", "nikto", "whatweb", "nmap", "sslyze", "wapiti"])}
                className="px-1.5 py-0.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              >
                All
              </button>
              <button
                type="button"
                onClick={() => setScanners(["nuclei", "whatweb"])}
                className="px-1.5 py-0.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              >
                Fast
              </button>
            </div>
            {ALL_SCANNERS.map((s) => {
              const active = scanners.includes(s.id);
              return (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => toggleScanner(s.id)}
                  className={`flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs transition-all cursor-pointer select-none ${
                    active
                      ? "border-blue-500/40 bg-blue-500/10 text-blue-300 font-medium"
                      : "border-slate-800 bg-slate-900/40 text-slate-500 hover:border-slate-700 hover:text-slate-300"
                  }`}
                >
                  {s.icon}
                  <span>{s.label}</span>
                </button>
              );
            })}
          </div>

          <button
            type="button"
            onClick={() => setShowScopePanel(!showScopePanel)}
            className={`flex items-center gap-1 text-xs transition-colors px-2 py-1 rounded cursor-pointer ${
              showScopePanel
                ? "text-blue-300 bg-blue-500/10 border border-blue-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Sliders size={12} />
            <span>Scope Perimeter</span>
            {showScopePanel ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          </button>
        </div>

        {/* Scope Management Panel */}
        <AnimatePresence>
          {showScopePanel && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-4 text-xs"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
                <span className="font-semibold text-slate-200">Scan Scope Perimeter & Rules</span>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] text-slate-400">Mode:</span>
                  <div className="flex rounded border border-slate-700 bg-slate-950 p-0.5">
                    <button
                      type="button"
                      onClick={() => setScopeMode("strict")}
                      className={`px-2 py-0.5 rounded text-[11px] cursor-pointer ${
                        scopeMode === "strict" ? "bg-blue-600 text-white font-medium" : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      Strict Host
                    </button>
                    <button
                      type="button"
                      onClick={() => setScopeMode("wildcard")}
                      className={`px-2 py-0.5 rounded text-[11px] cursor-pointer ${
                        scopeMode === "wildcard" ? "bg-blue-600 text-white font-medium" : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      Wildcard (*.{activeDomain})
                    </button>
                    <button
                      type="button"
                      onClick={() => setScopeMode("custom")}
                      className={`px-2 py-0.5 rounded text-[11px] cursor-pointer ${
                        scopeMode === "custom" ? "bg-blue-600 text-white font-medium" : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      Custom Rules
                    </button>
                  </div>
                </div>
              </div>

              {/* Active Rules Breakdown */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* In Scope Allow List */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider">
                      ✔ In-Scope Allowed Targets
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {scopeMode === "wildcard"
                        ? `*.${activeDomain}, ${activeDomain}`
                        : scopeMode === "strict"
                        ? activeDomain
                        : `${customInScope.length} custom pattern(s)`}
                    </span>
                  </div>

                  {scopeMode === "custom" ? (
                    <div className="space-y-2">
                      <div className="flex gap-2">
                        <input
                          type="text"
                          value={customInInput}
                          onChange={(e) => setCustomInInput(e.target.value)}
                          onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), handleAddInScope())}
                          placeholder="e.g. *.sub.domain.com"
                          className="flex-1 rounded border border-slate-700 bg-slate-950 px-2.5 py-1 text-xs text-slate-100 font-mono placeholder:text-slate-600 outline-none focus:border-emerald-500"
                        />
                        <button
                          type="button"
                          onClick={handleAddInScope}
                          className="rounded bg-emerald-600/20 border border-emerald-500/30 px-2.5 py-1 text-xs text-emerald-300 hover:bg-emerald-600/30 cursor-pointer"
                        >
                          Add
                        </button>
                      </div>
                      <div className="flex flex-wrap gap-1">
                        {customInScope.map((rule) => (
                          <span
                            key={rule}
                            className="flex items-center gap-1 rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-[11px] font-mono text-emerald-300"
                          >
                            <span>{rule}</span>
                            <X size={11} className="cursor-pointer hover:text-emerald-100" onClick={() => handleRemoveInScope(rule)} />
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="rounded border border-slate-800 bg-slate-950/40 p-2 text-xs font-mono text-slate-300">
                      {scopeMode === "wildcard" ? (
                        <span>Allowed: <code className="text-emerald-400">*.{activeDomain}</code> and <code className="text-emerald-400">{activeDomain}</code></span>
                      ) : (
                        <span>Allowed: Exact host <code className="text-emerald-400">{activeDomain}</code></span>
                      )}
                    </div>
                  )}
                </div>

                {/* Out of Scope Deny List */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold text-rose-400 uppercase tracking-wider">
                      ✖ Out-of-Scope Exclusions (Deny List)
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">{outOfScope.length} rule(s)</span>
                  </div>

                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={outOfScopeInput}
                      onChange={(e) => setOutOfScopeInput(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), handleAddOutOfScope())}
                      placeholder="e.g. logout, auth.*, billing"
                      className="flex-1 rounded border border-slate-700 bg-slate-950 px-2.5 py-1 text-xs text-slate-100 font-mono placeholder:text-slate-600 outline-none focus:border-rose-500"
                    />
                    <button
                      type="button"
                      onClick={() => handleAddOutOfScope()}
                      className="rounded bg-rose-600/20 border border-rose-500/30 px-2.5 py-1 text-xs text-rose-300 hover:bg-rose-600/30 cursor-pointer"
                    >
                      Exclude
                    </button>
                  </div>

                  <div className="flex flex-wrap gap-1">
                    {outOfScope.map((rule) => (
                      <span
                        key={rule}
                        className="flex items-center gap-1 rounded bg-rose-500/10 border border-rose-500/30 px-2 py-0.5 text-[11px] font-mono text-rose-300"
                      >
                        <span>{rule}</span>
                        <X size={11} className="cursor-pointer hover:text-rose-100" onClick={() => handleRemoveOutOfScope(rule)} />
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Target Reachability Live Banner */}
        <AnimatePresence>
          {probeResult && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="pt-2 border-t border-slate-800/60"
            >
              {probeResult.is_alive ? (
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-xs font-mono text-emerald-400">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 size={14} className="text-emerald-400 shrink-0" />
                    <span>Host Reachable</span>
                    <span className="text-slate-600">•</span>
                    <span>IP: {probeResult.ip || "127.0.0.1"}</span>
                    <span className="text-slate-600">•</span>
                    <span>HTTP {probeResult.status_code || 200}</span>
                    <span className="text-slate-600">•</span>
                    <span>{probeResult.latency_ms}ms RTT</span>
                  </div>
                  <span className="text-[11px] text-slate-400">{probeResult.server || "Server"}</span>
                </div>
              ) : (
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-rose-500/20 bg-rose-500/10 px-3 py-2 text-xs font-mono text-rose-400">
                  <div className="flex items-center gap-2">
                    <AlertCircle size={14} className="text-rose-400 shrink-0" />
                    <span>{probeResult.error}</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {probeResult.error?.includes("scanme.nmap.org") && (
                      <button
                        type="button"
                        onClick={() => applySuggestion("scanme.nmap.org")}
                        className="rounded bg-blue-500/20 px-2 py-0.5 text-[11px] font-medium text-blue-200 hover:bg-blue-500/30"
                      >
                        Use scanme.nmap.org
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => {
                        setProbeResult({
                          target: target.trim(),
                          hostname: activeDomain,
                          is_alive: true,
                          ip: "45.33.32.156",
                          status_code: 200,
                          latency_ms: 20,
                          server: "Fallback IP Mode (45.33.32.156)",
                          scheme: "http",
                          error: null,
                        });
                      }}
                      className="rounded bg-amber-500/20 border border-amber-500/30 px-2 py-0.5 text-[11px] font-medium text-amber-300 hover:bg-amber-500/30 transition-all"
                    >
                      Bypass DNS (Use Fallback IP 45.33.32.156)
                    </button>
                  </div>
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </form>
    </div>
  );
}
