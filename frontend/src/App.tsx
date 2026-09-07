import { useEffect, useRef, useState } from "react";
import { API_BASE_URL, ApiUnreachableError, checkApiHealth, getScanResults, getScanStatus, startScan } from "./api";
import { CorrelatedFindingsTable } from "./components/CorrelatedFindingsTable";
import { LiveTerminal } from "./components/LiveTerminal";
import { RawFindingsPanel } from "./components/RawFindingsPanel";
import { ScanForm } from "./components/ScanForm";
import { ScannerProgressList } from "./components/ScannerProgressList";
import { SeverityBreakdownCard } from "./components/SeverityBreakdownCard";
import { Sidebar, type NavTab } from "./components/Sidebar";
import { ExecutiveMetrics } from "./components/ExecutiveMetrics";
import { ApiTopologyGraph } from "./components/ApiTopologyGraph";
import { AssetInventoryTable } from "./components/AssetInventoryTable";
import { LoginView } from "./components/LoginView";
import type { ScannerName, ScanResultsResponse, ScanStatusResponse } from "./types";
import {
  Target,
  Download,
  RotateCw,
  GitBranch,
  ShieldAlert,
  Terminal,
  Cpu,
  Layers,
  ChevronRight,
  LogOut,
  UserCheck,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

type ApiState = "checking" | "online" | "offline";

export default function App() {
  // Authentication State
  const [user, setUser] = useState<{ username: string; role: string } | null>(() => {
    const saved = localStorage.getItem("pentest_user");
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return null;
      }
    }
    return null;
  });

  const [apiState, setApiState] = useState<ApiState>("checking");
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [results, setResults] = useState<ScanResultsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<NavTab>("overview");
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    checkApiHealth().then((ok) => setApiState(ok ? "online" : "offline"));
  }, []);

  useEffect(() => {
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

  function handleLogin(username: string) {
    const userData = { username, role: "SecOps Lead (Admin)" };
    localStorage.setItem("pentest_user", JSON.stringify(userData));
    setUser(userData);
  }

  function handleLogout() {
    localStorage.removeItem("pentest_user");
    setUser(null);
  }

  async function handleStart(target: string, scanners: ScannerName[], profile: string) {
    setError(null);
    setResults(null);
    try {
      const initial = await startScan(target, scanners, profile);
      setStatus(initial);

      pollRef.current = window.setInterval(async () => {
        try {
          const next = await getScanStatus(initial.scan_id);
          setStatus(next);

          // Progressive streaming: fetch and render results immediately as each scanner completes or finds vulnerabilities
          const anyProgress = next.scanners.some(
            (s) => s.status === "completed" || (s.findings_count ?? 0) > 0
          );
          if (anyProgress) {
            try {
              const currentResults = await getScanResults(initial.scan_id);
              setResults(currentResults);
            } catch {
              // Ignore transient polling error while job completes
            }
          }

          if (next.overall_status === "completed" || next.overall_status === "error") {
            if (pollRef.current) window.clearInterval(pollRef.current);
            const finalResults = await getScanResults(initial.scan_id);
            setResults(finalResults);
          }
        } catch (err) {
          if (pollRef.current) window.clearInterval(pollRef.current);
          setError(err instanceof Error ? err.message : "Polling failed");
        }
      }, 700);
    } catch (err) {
      setError(err instanceof ApiUnreachableError ? err.message : (err as Error).message);
    }
  }

  function handleDownloadReport(format: "json" | "summary") {
    if (!results) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `pentest-report-${results.target}-${format}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // If user is not authenticated, render Login Portal
  if (!user) {
    return <LoginView onLogin={handleLogin} />;
  }

  const isRunning = status?.overall_status === "running" || status?.overall_status === "queued";
  const currentLogs = status?.logs || results?.logs || [];
  const currentTarget = status?.target || results?.target || "scanme.nmap.org";

  // Dynamic user-based metrics: 0 by default, populated ONLY with real findings
  const distribution = results
    ? results.severity_distribution
    : { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const totalFindings = results ? results.raw_findings.length : 0;
  const duplicateGroups = results ? results.duplicate_groups : 0;
  const rawFindings = results ? results.raw_findings : [];

  return (
    <div className="flex min-h-screen text-[var(--text-primary)] bg-[#070a0f]">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        threatCount={totalFindings}
        logsCount={currentLogs.length}
        user={user}
        onLogout={handleLogout}
      />

      <div className="min-w-0 flex-1 relative flex flex-col">
        {/* Strix/ZeroThreat Executive Top Bar */}
        <header className="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-4 border-b border-gray-800/80 bg-[#080c14]/90 backdrop-blur-xl px-8 py-4">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-xs font-mono text-gray-400">
              <span className="text-gray-500">Targets</span>
              <ChevronRight size={14} className="text-gray-600" />
              <span className="font-bold text-cyan-300 font-mono flex items-center gap-1.5">
                <Target size={14} className="text-cyan-400" />
                {currentTarget}
              </span>
            </div>

            <span className="rounded-md border border-gray-700/60 bg-black/40 px-2 py-0.5 text-[10px] font-mono font-bold text-gray-400">
              v2.4 (Live)
            </span>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 rounded-xl border border-gray-800 bg-black/40 px-3 py-1.5 text-xs font-mono">
              <UserCheck size={14} className="text-emerald-400" />
              <span className="text-white font-bold">{user.username}</span>
              <span className="text-gray-500">•</span>
              <span className="text-cyan-400 text-[11px]">SecOps Clearance</span>
            </div>

            <button
              onClick={() => handleStart(currentTarget, ["nuclei", "zap", "nikto"], "web")}
              disabled={!!isRunning}
              className="flex items-center gap-1.5 rounded-xl border border-gray-700/80 bg-gray-900/80 hover:bg-gray-800 px-3.5 py-1.5 text-xs font-semibold text-gray-200 transition-all disabled:opacity-40 cursor-pointer"
            >
              <RotateCw size={13} className={isRunning ? "animate-spin text-cyan-400" : ""} />
              <span>Rescan Target</span>
            </button>

            <button
              onClick={() => handleDownloadReport("json")}
              disabled={!results}
              className="flex items-center gap-1.5 rounded-xl border border-blue-500/40 bg-blue-600/20 hover:bg-blue-600 px-3.5 py-1.5 text-xs font-semibold text-blue-300 hover:text-white transition-all disabled:opacity-40 shadow-sm cursor-pointer"
            >
              <Download size={13} />
              <span>Download Report</span>
            </button>

            <button
              onClick={handleLogout}
              title="Sign Out"
              className="flex items-center gap-1 rounded-xl border border-gray-800 bg-black/40 hover:bg-rose-500/20 hover:border-rose-500/40 px-2.5 py-1.5 text-xs font-medium text-gray-400 hover:text-rose-300 transition-colors cursor-pointer"
            >
              <LogOut size={13} />
            </button>
          </div>
        </header>

        {/* Secondary Navigation Tabs (Escape/ZeroThreat style) */}
        <div className="flex items-center gap-1 border-b border-gray-800/60 bg-black/40 px-8 py-2 overflow-x-auto text-xs">
          {[
            { id: "overview" as NavTab, label: "Overview & ASM", icon: <Layers size={14} /> },
            { id: "topology" as NavTab, label: "API Attack Graph", icon: <GitBranch size={14} />, badge: "Live Packets" },
            { id: "findings" as NavTab, label: "Threats & Findings", icon: <ShieldAlert size={14} />, count: totalFindings },
            { id: "terminal" as NavTab, label: "Live Console", icon: <Terminal size={14} />, count: currentLogs.length, pulse: isRunning },
            { id: "scanners" as NavTab, label: "Engine Cluster", icon: <Cpu size={14} /> },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg font-semibold transition-all select-none cursor-pointer ${
                activeTab === tab.id
                  ? "bg-blue-600/20 border border-blue-500/40 text-cyan-300 shadow-sm shadow-blue-500/10 font-bold"
                  : "text-gray-400 hover:text-gray-200 hover:bg-white/[0.03]"
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
              {tab.badge && (
                <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  {tab.badge}
                </span>
              )}
              {tab.count !== undefined && tab.count > 0 && (
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-full bg-rose-950/80 text-rose-300 border border-rose-800/40">
                  {tab.count}
                </span>
              )}
              {tab.pulse && <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-ping" />}
            </button>
          ))}
        </div>

        {/* Main Content Body */}
        <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col gap-8 px-6 py-8 md:px-10">
          <AnimatePresence>
            {apiState === "offline" && (
              <motion.div
                initial={{ opacity: 0, y: -15 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-5 py-3 text-xs text-rose-300 flex items-center justify-between"
              >
                <span>
                  <strong>Backend Service Offline</strong> — API unreachable at <code className="font-mono bg-black/40 px-1 py-0.5 rounded">{API_BASE_URL}</code>. Ensure docker containers are running.
                </span>
              </motion.div>
            )}

            {error && (
              <motion.div
                initial={{ opacity: 0, y: -15 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-5 py-3.5 text-xs text-rose-300 shadow-lg shadow-rose-500/5"
              >
                {error}
              </motion.div>
            )}
          </AnimatePresence>

          {/* TAB 1: OVERVIEW & ATTACK SURFACE MANAGEMENT */}
          {activeTab === "overview" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">
              {/* Strix Top KPI Row */}
              <ExecutiveMetrics
                distribution={distribution}
                totalFindings={totalFindings}
                duplicateGroups={duplicateGroups}
                isScanning={!!isRunning}
              />

              {/* Scan Launcher Card */}
              <ScanForm onStart={handleStart} disabled={!!isRunning} />

              {/* Live Progress Card */}
              {status && (
                <ScannerProgressList
                  scanners={status.scanners}
                  onOpenTerminal={() => setActiveTab("terminal")}
                  terminalOpen={false}
                  logsCount={currentLogs.length}
                />
              )}

              {/* Escape.dev Style Asset Inventory */}
              <AssetInventoryTable
                target={currentTarget}
                findings={rawFindings}
                onTriggerScan={(endpoint) => handleStart(endpoint, ["nuclei", "zap"], "web")}
              />
            </motion.div>
          )}

          {/* TAB 2: API ATTACK GRAPH (ESCAPE.DEV TOPOLOGY) */}
          {activeTab === "topology" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              <ApiTopologyGraph
                target={currentTarget}
                findings={rawFindings}
                isScanning={!!isRunning}
              />
              <AssetInventoryTable
                target={currentTarget}
                findings={rawFindings}
                onTriggerScan={(endpoint) => handleStart(endpoint, ["nuclei", "zap"], "web")}
              />
            </motion.div>
          )}

          {/* TAB 3: THREATS & FINDINGS */}
          {activeTab === "findings" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">
              <ExecutiveMetrics
                distribution={distribution}
                totalFindings={totalFindings}
                duplicateGroups={duplicateGroups}
                isScanning={!!isRunning}
              />

              {results && results.correlated_findings.length > 0 ? (
                <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
                  <div className="lg:col-span-2">
                    <CorrelatedFindingsTable findings={results.correlated_findings} />
                  </div>
                  <div className="lg:col-span-1">
                    <SeverityBreakdownCard distribution={results.severity_distribution} />
                  </div>
                </div>
              ) : (
                <div className="p-12 text-center text-gray-500 bg-white/[0.02] rounded-2xl border border-gray-800">
                  <ShieldAlert size={36} className="mx-auto mb-3 text-gray-600" />
                  <p className="text-base font-bold text-gray-300">
                    {totalFindings === 0 && results ? "Target Verified Clean — 0 Vulnerabilities Flagged" : "Awaiting Scan Execution"}
                  </p>
                  <p className="text-xs text-gray-500 mt-1.5 max-w-md mx-auto">
                    {results
                      ? "The scanner cluster completed testing against the specified target. No high or critical security alerts were found."
                      : "Enter a live host or URL in the Overview tab to launch an automated assessment and populate real-time findings."}
                  </p>
                </div>
              )}

              {results && results.raw_findings.length > 0 && (
                <RawFindingsPanel findings={results.raw_findings} />
              )}
            </motion.div>
          )}

          {/* TAB 4: LIVE SCANNER CONSOLE */}
          {activeTab === "terminal" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              <LiveTerminal
                logs={currentLogs}
                isRunning={!!isRunning}
                isOpen={true}
                onToggle={() => {}}
              />
              {status && <ScannerProgressList scanners={status.scanners} />}
            </motion.div>
          )}

          {/* TAB 5: SCANNER CLUSTER */}
          {activeTab === "scanners" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">
              {status && <ScannerProgressList scanners={status.scanners} />}
              <LiveTerminal
                logs={currentLogs}
                isRunning={!!isRunning}
                isOpen={true}
                onToggle={() => {}}
              />
            </motion.div>
          )}
        </main>
      </div>
    </div>
  );
}
