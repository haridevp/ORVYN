import { useState, useEffect, useMemo } from "react";
import type { ScannerName, TargetProbeResponse } from "../types";
import { probeTarget } from "../api";
import {
  Play,
  Terminal,
  Zap,
  Shield,
  Search,
  Radio,
  CheckCircle,
  AlertTriangle,
  Activity,
  Globe,
  Plus,
  X,
  Ban,
  Sliders,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const ALL_SCANNERS: { id: ScannerName; label: string; icon: React.ReactNode; color: string }[] = [
  { id: "nuclei", label: "Nuclei", icon: <FlameIcon size={14} />, color: "text-orange-400" },
  { id: "zap", label: "OWASP ZAP", icon: <Zap size={14} />, color: "text-blue-400" },
  { id: "nikto", label: "Nikto", icon: <Shield size={14} />, color: "text-purple-400" },
];

function FlameIcon({ size = 14 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/>
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
  const [isFocused, setIsFocused] = useState(false);

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

    // Determine final in_scope array
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
    <motion.form
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      onSubmit={handleSubmit}
      className={`relative overflow-hidden rounded-2xl glass-panel p-6 transition-all duration-300 ${
        isFocused ? "shadow-[var(--shadow-glow)] border-blue-500/30" : ""
      }`}
    >
      {/* Background glowing effect */}
      <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-purple-500/5 pointer-events-none" />

      <div className="relative z-10 flex flex-col gap-6 lg:flex-row lg:items-end">
        <div className="flex-1 group">
          <label className="mb-2 flex items-center justify-between text-sm font-semibold tracking-wide text-gray-300">
            <span className="flex items-center gap-2">
              <TargetIcon size={16} className="text-blue-400" />
              Target Host / URL
            </span>
            {isProbing && (
              <span className="flex items-center gap-1 text-[11px] font-mono text-cyan-400">
                <Radio size={12} className="animate-spin" />
                Probing Reachability...
              </span>
            )}
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
              <Search size={16} className="text-gray-500 group-focus-within:text-blue-400 transition-colors" />
            </div>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onFocus={() => setIsFocused(true)}
              onBlur={() => setIsFocused(false)}
              placeholder="e.g. github.com or scanme.nmap.org"
              className="w-full rounded-xl border border-gray-700/50 bg-black/40 pl-10 pr-4 py-3 text-sm text-white font-mono outline-none transition-all focus:border-blue-500/50 focus:bg-black/60 focus:ring-2 focus:ring-blue-500/20"
              minLength={3}
              required
            />
          </div>
        </div>

        <label className="lg:w-56">
          <span className="mb-2 flex items-center gap-2 text-sm font-semibold tracking-wide text-gray-300">
            <Terminal size={16} className="text-purple-400" />
            Scan Profile
          </span>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            className="w-full rounded-xl border border-gray-700/50 bg-black/40 px-4 py-3 text-sm text-white outline-none transition-all focus:border-purple-500/50 focus:ring-2 focus:ring-purple-500/20 cursor-pointer appearance-none"
          >
            <option value="recon" className="bg-gray-900">Recon (Fast ~15-25s)</option>
            <option value="web" className="bg-gray-900">Web (Standard ~45s)</option>
            <option value="full" className="bg-gray-900">Full (Comprehensive ~90s)</option>
            <option value="unlimited" className="bg-gray-900 font-bold text-cyan-300">Exhaustive (No Timeout • Deep Scan)</option>
          </select>
        </label>

        <div className="flex-1 xl:flex-none">
          <span className="mb-2 block text-sm font-semibold tracking-wide text-gray-300">Engines</span>
          <div className="flex flex-wrap gap-2">
            {ALL_SCANNERS.map(({ id, label, icon, color }) => {
              const checked = scanners.includes(id);
              return (
                <motion.button
                  type="button"
                  key={id}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={() => toggleScanner(id)}
                  aria-pressed={checked}
                  className={`flex items-center gap-2 rounded-xl border px-4 py-3 text-sm font-semibold transition-all cursor-pointer ${
                    checked
                      ? "border-blue-500/30 bg-blue-500/10 text-white shadow-[0_0_15px_rgba(59,130,246,0.15)]"
                      : "border-gray-700/50 bg-black/20 text-gray-400 hover:border-gray-500/50 hover:bg-gray-800/50"
                  }`}
                >
                  <span className={checked ? color : ""}>{icon}</span>
                  {label}
                </motion.button>
              );
            })}
          </div>
        </div>

        <motion.button
          type="submit"
          whileHover={{ scale: disabled || scanners.length === 0 ? 1 : 1.02 }}
          whileTap={{ scale: disabled || scanners.length === 0 ? 1 : 0.98 }}
          disabled={disabled || scanners.length === 0}
          className={`flex h-[46px] items-center gap-2 rounded-xl px-8 font-bold text-white transition-all cursor-pointer ${
            disabled || scanners.length === 0
              ? "bg-gray-800 text-gray-500 cursor-not-allowed border border-gray-700"
              : "bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 shadow-[0_0_20px_rgba(59,130,246,0.3)] border border-blue-400/20"
          }`}
        >
          {disabled ? (
            <>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ repeat: Infinity, duration: 1, ease: "linear" }}
              >
                <Zap size={16} />
              </motion.div>
              Engines Running...
            </>
          ) : (
            <>
              <Play size={16} fill="currentColor" />
              Launch Scan
            </>
          )}
        </motion.button>
      </div>

      {/* Target Scope & Perimeter Selector Bar */}
      <div className="mt-5 pt-4 border-t border-gray-800/70">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 text-xs font-semibold text-gray-300">
              <Globe size={14} className="text-cyan-400" />
              Perimeter Scope:
            </span>

            {/* Scope Mode Presets */}
            <div className="flex items-center rounded-lg border border-gray-800 bg-black/40 p-0.5 text-xs font-mono">
              <button
                type="button"
                onClick={() => setScopeMode("wildcard")}
                className={`rounded-md px-2.5 py-1 transition-all cursor-pointer ${
                  scopeMode === "wildcard"
                    ? "bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40 shadow-sm"
                    : "text-gray-400 hover:text-gray-200"
                }`}
                title="Includes the domain and all discovered subdomains"
              >
                *.{activeDomain} (Wildcard Subdomains)
              </button>
              <button
                type="button"
                onClick={() => setScopeMode("strict")}
                className={`rounded-md px-2.5 py-1 transition-all cursor-pointer ${
                  scopeMode === "strict"
                    ? "bg-blue-500/20 text-blue-300 font-bold border border-blue-500/40 shadow-sm"
                    : "text-gray-400 hover:text-gray-200"
                }`}
                title="Restricts scan strictly to single hostname"
              >
                {activeDomain} (Exact Host Only)
              </button>
              <button
                type="button"
                onClick={() => {
                  setScopeMode("custom");
                  setShowScopePanel(true);
                }}
                className={`rounded-md px-2.5 py-1 transition-all cursor-pointer ${
                  scopeMode === "custom"
                    ? "bg-purple-500/20 text-purple-300 font-bold border border-purple-500/40 shadow-sm"
                    : "text-gray-400 hover:text-gray-200"
                }`}
                title="Define custom in-scope & out-of-scope rules"
              >
                Custom Rules
              </button>
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowScopePanel(!showScopePanel)}
            className="flex items-center gap-1 text-xs font-mono text-gray-400 hover:text-cyan-300 transition-colors cursor-pointer"
          >
            <Sliders size={12} />
            <span>{showScopePanel ? "Hide Scope Details" : "Configure Scope & Exclusions"}</span>
            {outOfScope.length > 0 && (
              <span className="rounded-full bg-rose-950/80 border border-rose-800/60 px-1.5 py-0.2 text-[10px] text-rose-300 font-bold">
                {outOfScope.length} excluded
              </span>
            )}
            {showScopePanel ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>

        {/* Expandable Scope & Exclusion Drawer */}
        <AnimatePresence>
          {showScopePanel && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 rounded-xl border border-gray-800/80 bg-black/40 p-4 text-xs font-mono space-y-4"
            >
              {/* In-Scope Specification */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle size={13} />
                    In-Scope Perimeter (Included in Assessment)
                  </span>
                  <span className="text-[11px] text-gray-500">
                    {scopeMode === "wildcard"
                      ? `Default: *.${activeDomain} will scan all subdomains and paths`
                      : scopeMode === "strict"
                      ? `Strict: only ${activeDomain} will be scanned`
                      : "Custom in-scope patterns active"}
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-emerald-300 font-bold">
                    {scopeMode === "strict" ? activeDomain : `*.${activeDomain}`}
                  </span>
                  {customInScope.map((rule) => (
                    <span
                      key={rule}
                      className="flex items-center gap-1 rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-1 text-emerald-200"
                    >
                      {rule}
                      <button
                        type="button"
                        onClick={() => handleRemoveInScope(rule)}
                        className="text-gray-400 hover:text-rose-400 transition-colors cursor-pointer"
                      >
                        <X size={12} />
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
                      placeholder="e.g. *.api.target.com"
                      className="rounded-lg border border-gray-700 bg-gray-900/60 px-2.5 py-1 text-xs text-white outline-none focus:border-emerald-500/50"
                    />
                    <button
                      type="button"
                      onClick={handleAddInScope}
                      className="rounded-lg border border-emerald-500/40 bg-emerald-500/20 px-2 py-1 text-emerald-300 hover:bg-emerald-500 hover:text-black font-bold transition-all cursor-pointer"
                    >
                      <Plus size={12} />
                    </button>
                  </div>
                </div>
              </div>

              {/* Out-of-Scope Specification */}
              <div className="pt-3 border-t border-gray-800/60">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-rose-400 flex items-center gap-1.5">
                    <Ban size={13} />
                    Out-of-Scope Deny-List (Excluded from Scan & Results)
                  </span>
                  <span className="text-[11px] text-gray-500">
                    Bypasses sensitive paths, auth gateways, third parties, or destructive endpoints
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2 mb-2">
                  {outOfScope.length === 0 ? (
                    <span className="text-gray-500 italic text-[11px]">No exclusions defined (everything on scope will be tested)</span>
                  ) : (
                    outOfScope.map((rule) => (
                      <span
                        key={rule}
                        className="flex items-center gap-1 rounded-lg border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 text-rose-300 font-bold"
                      >
                        🚫 {rule}
                        <button
                          type="button"
                          onClick={() => handleRemoveOutOfScope(rule)}
                          title="Remove exclusion"
                          className="text-gray-400 hover:text-white transition-colors cursor-pointer ml-1"
                        >
                          <X size={12} />
                        </button>
                      </span>
                    ))
                  )}

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
                      placeholder="e.g. logout or auth.*"
                      className="rounded-lg border border-gray-700 bg-gray-900/60 px-2.5 py-1 text-xs text-white outline-none focus:border-rose-500/50"
                    />
                    <button
                      type="button"
                      onClick={() => handleAddOutOfScope()}
                      className="rounded-lg border border-rose-500/40 bg-rose-500/20 px-2 py-1 text-rose-300 hover:bg-rose-500 hover:text-white font-bold transition-all cursor-pointer"
                    >
                      Exclude
                    </button>
                  </div>
                </div>

                {/* Quick Add Suggestions */}
                <div className="flex items-center gap-1.5 text-[11px] text-gray-500">
                  <span>Quick Exclude:</span>
                  {[
                    "logout",
                    "auth.*",
                    "/admin/delete*",
                    "payment.*",
                    "*.thirdparty.com",
                  ].map((sugg) => (
                    <button
                      key={sugg}
                      type="button"
                      onClick={() => handleAddOutOfScope(sugg)}
                      disabled={outOfScope.includes(sugg)}
                      className="rounded border border-gray-800 bg-gray-900/60 px-2 py-0.5 text-gray-400 hover:text-rose-300 hover:border-rose-700/50 transition-colors disabled:opacity-30 cursor-pointer"
                    >
                      +{sugg}
                    </button>
                  ))}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Live Target Health Probe Banner */}
      <AnimatePresence>
        {probeResult && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-4 pt-3 border-t border-gray-800/80"
          >
            {probeResult.is_alive ? (
              <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-4 py-2.5 text-xs text-emerald-300 font-mono">
                <div className="flex items-center gap-2 font-bold">
                  <CheckCircle size={15} className="text-emerald-400" />
                  <span>Target Online & Verified</span>
                  <span className="text-gray-400 font-normal">•</span>
                  <span className="text-gray-300">HTTP {probeResult.status_code || 200}</span>
                  <span className="text-gray-400 font-normal">•</span>
                  <span className="text-cyan-300">{probeResult.latency_ms}ms RTT</span>
                  <span className="text-gray-400 font-normal">•</span>
                  <span className="text-gray-400 font-normal">{probeResult.server || "Web Server"}</span>
                </div>
                <div className="text-[11px] text-emerald-400/80">IP: {probeResult.ip}</div>
              </div>
            ) : (
              <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-300 font-mono">
                <div className="flex items-center gap-2">
                  <AlertTriangle size={15} className="text-rose-400 shrink-0" />
                  <span>{probeResult.error}</span>
                </div>
                {probeResult.error?.includes("scanme.nmap.org") && (
                  <button
                    type="button"
                    onClick={() => applySuggestion("scanme.nmap.org")}
                    className="rounded bg-rose-500/20 border border-rose-500/40 px-2 py-0.5 text-[11px] font-bold text-rose-200 hover:bg-rose-500 hover:text-white transition-colors cursor-pointer"
                  >
                    Click to use scanme.nmap.org
                  </button>
                )}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Speed & Optimization Note */}
      <div className="mt-4 flex items-center justify-between text-[11px] text-gray-500 font-mono">
        <span className="flex items-center gap-1.5">
          <Activity size={12} className="text-cyan-400" />
          Perimeter Scope: <strong className="text-cyan-300">{scopeMode === "strict" ? activeDomain : `*.${activeDomain}`}</strong>
          {outOfScope.length > 0 && <span> • ({outOfScope.length} excluded)</span>}
        </span>
        <span className="text-gray-400">
          Tip: Select &quot;Exhaustive (No Timeout)&quot; to disable all timeout limits.
        </span>
      </div>
    </motion.form>
  );
}

function TargetIcon({ size, className }: { size: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <circle cx="12" cy="12" r="10"/>
      <circle cx="12" cy="12" r="6"/>
      <circle cx="12" cy="12" r="2"/>
    </svg>
  );
}
