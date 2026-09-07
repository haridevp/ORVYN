import { useState, useEffect, useMemo } from "react";
import type { ScannerName, TargetProbeResponse } from "../types";
import { probeTarget } from "../api";
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
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const ALL_SCANNERS: { id: ScannerName; label: string; icon: React.ReactNode }[] = [
  { id: "nuclei", label: "Nuclei (Templates)", icon: <FlameIcon size={14} /> },
  { id: "zap", label: "OWASP ZAP (Spider & DAST)", icon: <Zap size={14} /> },
  { id: "nikto", label: "Nikto (Web Server Audit)", icon: <Shield size={14} /> },
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
  ) => void;
  disabled: boolean;
}

export function ScanForm({ onStart, disabled }: Props) {
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("web");
  const [scanners, setScanners] = useState<ScannerName[]>(["nuclei", "zap", "nikto"]);

  // Scope & Perimeter Management state
  const [scopeMode, setScopeMode] = useState<"wildcard" | "strict" | "custom">("wildcard");
  const [showScopePanel, setShowScopePanel] = useState(false);
  const [customInScope, setCustomInScope] = useState<string[]>([]);
  const [customInInput, setCustomInInput] = useState("");
  const [outOfScope, setOutOfScope] = useState<string[]>(["logout", "auth.*"]);
  const [outOfScopeInput, setOutOfScopeInput] = useState("");

  // Live pre-flight probe state
  const [isProbing, setIsProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<TargetProbeResponse | null>(null);

  const activeDomain = useMemo(() => extractDomain(target || "target.com"), [target]);

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

    onStart(target.trim(), scanners, profile, effectiveInScope, outOfScope);
  }

  function applySuggestion(suggested: string) {
    setTarget(suggested);
  }

  return (
    <div className="enterprise-panel p-5 space-y-4">
      <form onSubmit={handleSubmit} className="space-y-4">
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
                <option value="recon">Reconnaissance (~20s)</option>
                <option value="web">Web Application (~45s)</option>
                <option value="full">Comprehensive Full (~85s)</option>
                <option value="unlimited">Exhaustive (No Timeout)</option>
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
                  <span>Start Penetration Assessment</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Engine Checkbox Pills */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/60">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mr-1">
              Engines:
            </span>
            {ALL_SCANNERS.map(({ id, label, icon }) => {
              const active = scanners.includes(id);
              return (
                <button
                  type="button"
                  key={id}
                  onClick={() => toggleScanner(id)}
                  className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-all cursor-pointer border ${
                    active
                      ? "border-blue-500/40 bg-blue-500/15 text-blue-300"
                      : "border-slate-800 bg-slate-900/60 text-slate-400 hover:border-slate-700 hover:text-slate-300"
                  }`}
                >
                  <span className={active ? "text-blue-400" : "text-slate-500"}>{icon}</span>
                  <span>{label}</span>
                </button>
              );
            })}
          </div>

          <button
            type="button"
            onClick={() => setShowScopePanel(!showScopePanel)}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
          >
            <Sliders size={12} className="text-slate-400" />
            <span>Scope Rules ({outOfScope.length} excluded)</span>
            {showScopePanel ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>
        </div>

        {/* Expandable Scope & Exclusion Drawer */}
        <AnimatePresence>
          {showScopePanel && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="rounded-lg border border-slate-800/80 bg-slate-900/60 p-3.5 text-xs space-y-3"
            >
              {/* Scope Presets */}
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-slate-400 text-[11px] font-medium">Mode:</span>
                <div className="flex rounded-md border border-slate-800 bg-slate-950 p-0.5 text-xs font-mono">
                  <button
                    type="button"
                    onClick={() => setScopeMode("wildcard")}
                    className={`rounded px-2 py-0.5 transition-all ${
                      scopeMode === "wildcard"
                        ? "bg-blue-600 text-white font-semibold shadow-xs"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    *.{activeDomain} (Wildcard)
                  </button>
                  <button
                    type="button"
                    onClick={() => setScopeMode("strict")}
                    className={`rounded px-2 py-0.5 transition-all ${
                      scopeMode === "strict"
                        ? "bg-blue-600 text-white font-semibold shadow-xs"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {activeDomain} (Strict Host)
                  </button>
                  <button
                    type="button"
                    onClick={() => setScopeMode("custom")}
                    className={`rounded px-2 py-0.5 transition-all ${
                      scopeMode === "custom"
                        ? "bg-blue-600 text-white font-semibold shadow-xs"
                        : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Custom
                  </button>
                </div>
              </div>

              {/* In-Scope Rules */}
              <div className="space-y-1.5">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  In-Scope Rules
                </span>
                <div className="flex flex-wrap items-center gap-1.5 font-mono">
                  <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-400 text-[11px]">
                    {scopeMode === "strict" ? activeDomain : `*.${activeDomain}`}
                  </span>
                  {customInScope.map((rule) => (
                    <span
                      key={rule}
                      className="flex items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-emerald-400 text-[11px]"
                    >
                      {rule}
                      <button
                        type="button"
                        onClick={() => handleRemoveInScope(rule)}
                        className="text-slate-400 hover:text-rose-400"
                      >
                        <X size={11} />
                      </button>
                    </span>
                  ))}
                  <div className="flex items-center gap-1">
                    <input
                      type="text"
                      value={customInInput}
                      onChange={(e) => setCustomInInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          handleAddInScope();
                        }
                      }}
                      placeholder="Add pattern..."
                      className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 text-[11px] text-white outline-none focus:border-blue-500"
                    />
                    <button
                      type="button"
                      onClick={handleAddInScope}
                      className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300 hover:bg-slate-700"
                    >
                      +
                    </button>
                  </div>
                </div>
              </div>

              {/* Out-of-Scope Deny List */}
              <div className="space-y-1.5 pt-2 border-t border-slate-800/60">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Out-of-Scope Deny-List
                </span>
                <div className="flex flex-wrap items-center gap-1.5 font-mono">
                  {outOfScope.map((rule) => (
                    <span
                      key={rule}
                      className="flex items-center gap-1 rounded border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-rose-300 text-[11px]"
                    >
                      {rule}
                      <button
                        type="button"
                        onClick={() => handleRemoveOutOfScope(rule)}
                        className="text-slate-400 hover:text-rose-200"
                      >
                        <X size={11} />
                      </button>
                    </span>
                  ))}
                  <div className="flex items-center gap-1">
                    <input
                      type="text"
                      value={outOfScopeInput}
                      onChange={(e) => setOutOfScopeInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          handleAddOutOfScope();
                        }
                      }}
                      placeholder="Exclude pattern..."
                      className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 text-[11px] text-white outline-none focus:border-rose-500"
                    />
                    <button
                      type="button"
                      onClick={() => handleAddOutOfScope()}
                      className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300 hover:bg-slate-700"
                    >
                      +
                    </button>
                  </div>
                </div>

                {/* Quick Add suggestions */}
                <div className="flex items-center gap-1.5 text-[11px] text-slate-500 pt-1">
                  <span>Quick Exclude:</span>
                  {["logout", "auth.*", "admin/delete*", "payment.*"].map((sugg) => (
                    <button
                      key={sugg}
                      type="button"
                      onClick={() => handleAddOutOfScope(sugg)}
                      disabled={outOfScope.includes(sugg)}
                      className="rounded border border-slate-800 bg-slate-950 px-1.5 py-0.5 text-slate-400 hover:text-slate-200 disabled:opacity-40"
                    >
                      +{sugg}
                    </button>
                  ))}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Live Target Health Probe Banner */}
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
                  {probeResult.error?.includes("scanme.nmap.org") && (
                    <button
                      type="button"
                      onClick={() => applySuggestion("scanme.nmap.org")}
                      className="rounded bg-rose-500/20 px-2 py-0.5 text-[11px] font-medium text-rose-200 hover:bg-rose-500/30"
                    >
                      Use scanme.nmap.org
                    </button>
                  )}
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </form>
    </div>
  );
}
