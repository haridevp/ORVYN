import { useEffect, useRef, useState } from "react";
import {
  API_BASE_URL,
  ApiUnreachableError,
  checkApiHealth,
  getScanResults,
  getScanStatus,
  startScan,
  cancelScan,
  downloadScanReportPdf,
} from "./api";
import { openPrintablePentestReport } from "./utils/pdfExport";
import { WildcardPerimeterTracker } from "./components/WildcardPerimeterTracker";
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
import { LiveFindingsFeed } from "./components/LiveFindingsFeed";
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
  StopCircle,
  FileText,
  Printer,
  ChevronDown,
  Activity,
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
  const [allScans, setAllScans] = useState<ScanStatusResponse[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [results, setResults] = useState<ScanResultsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<NavTab>("overview");
  const [showExportMenu, setShowExportMenu] = useState(false);

  const selectedScanIdRef = useRef<string | null>(null);
  const pollersRef = useRef<Map<string, number>>(new Map());

  useEffect(() => {
    selectedScanIdRef.current = selectedScanId;
  }, [selectedScanId]);

  useEffect(() => {
    checkApiHealth().then((ok) => setApiState(ok ? "online" : "offline"));
  }, []);

  useEffect(() => {
    const pollers = pollersRef.current;
    return () => {
      pollers.forEach((intervalId) => window.clearInterval(intervalId));
      pollers.clear();
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

  async function handleSelectScan(scanId: string) {
    setSelectedScanId(scanId);
    const existing = allScans.find((s) => s.scan_id === scanId);
    if (existing) {
      setStatus(existing);
    }
    try {
      const res = await getScanResults(scanId);
      setResults(res);
    } catch {
      // Job may still be in initial progress
    }
  }

  async function handleCancelScan(scanIdToCancel?: string) {
    const id = scanIdToCancel || selectedScanId || status?.scan_id;
    if (!id) return;
    try {
      const updated = await cancelScan(id);
      setStatus(updated);
      setAllScans((prev) => prev.map((s) => (s.scan_id === id ? updated : s)));
    } catch {
      setStatus((prev) => (prev ? { ...prev, overall_status: "cancelled" } : null));
      setAllScans((prev) =>
        prev.map((s) => (s.scan_id === id ? { ...s, overall_status: "cancelled" } : s))
      );
    }
    const poller = pollersRef.current.get(id);
    if (poller) {
      window.clearInterval(poller);
      pollersRef.current.delete(id);
    }
  }

  async function handleStart(
    target: string,
    scanners: ScannerName[],
    profile: string,
    inScope?: string[],
    outOfScope?: string[],
  ) {
    setError(null);
    try {
      const initial = await startScan(target, scanners, profile, inScope, outOfScope);
      setAllScans((prev) => [initial, ...prev.filter((s) => s.scan_id !== initial.scan_id)]);
      setSelectedScanId(initial.scan_id);
      setStatus(initial);
      const existingPoller = pollersRef.current.get(initial.scan_id);
      if (existingPoller) {
        window.clearInterval(existingPoller);
        pollersRef.current.delete(initial.scan_id);
      }

      const intervalId = window.setInterval(async () => {
        try {
          const next = await getScanStatus(initial.scan_id);
          setAllScans((prev) =>
            prev.map((s) => (s.scan_id === initial.scan_id ? next : s))
          );

          if (selectedScanIdRef.current === initial.scan_id) {
            setStatus(next);
          }

          const anyProgress = next.scanners.some(
            (s) => s.status === "completed" || (s.findings_count ?? 0) > 0
          );
          if (anyProgress) {
            try {
              const currentResults = await getScanResults(initial.scan_id);
              if (selectedScanIdRef.current === initial.scan_id) {
                setResults(currentResults);
              }
            } catch {
              // Transient polling catch
            }
          }

          if (
            next.overall_status === "completed" ||
            next.overall_status === "error" ||
            next.overall_status === "cancelled"
          ) {
            window.clearInterval(intervalId);
            pollersRef.current.delete(initial.scan_id);
            try {
              const finalResults = await getScanResults(initial.scan_id);
              if (selectedScanIdRef.current === initial.scan_id) {
                setResults(finalResults);
              }
            } catch {
              // Ignore
            }
          }
        } catch {
          window.clearInterval(intervalId);
          pollersRef.current.delete(initial.scan_id);
        }
      }, 1000);

      pollersRef.current.set(initial.scan_id, intervalId);
    } catch (err) {
      setError(err instanceof ApiUnreachableError ? err.message : (err as Error).message);
    }
  }

  async function handleDownloadReport(format: "pdf" | "print" | "json" | "markdown") {
    setShowExportMenu(false);
    if (!results) return;

    if (format === "print") {
      openPrintablePentestReport(results);
      return;
    }

    if (format === "pdf") {
      try {
        await downloadScanReportPdf(results.scan_id, results.target);
      } catch {
        openPrintablePentestReport(results);
      }
      return;
    }

    if (format === "json") {
      const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pentest-report-${results.target}.json`;
      a.click();
      URL.revokeObjectURL(url);
      return;
    }

    if (format === "markdown") {
      let md = `# Penetration Testing Executive Report: ${results.target}\n\n`;
      md += `- **Generated At:** ${new Date().toUTCString()}\n`;
      md += `- **Scan ID:** ${results.scan_id}\n`;
      md += `- **Target Perimeter:** \`${results.target}\`\n`;
      md += `\n## Severity Distribution\n`;
      for (const [sev, count] of Object.entries(results.severity_distribution || {})) {
        md += `- **${sev.toUpperCase()}:** ${count}\n`;
      }
      md += `\n## Correlated Vulnerabilities (${results.correlated_findings.length})\n\n`;
      for (const f of results.correlated_findings) {
        md += `### [${f.severity.toUpperCase()}] ${f.vulnerability}\n`;
        md += `- **Target:** ${f.target}\n`;
        md += `- **Confidence:** ${f.confidence}%\n`;
        md += `- **Engines:** ${f.contributing_tools.join(", ")}\n`;
        md += `- **Description:** ${f.description}\n`;
        if (f.evidence && f.evidence.length > 0) {
          md += `- **Evidence:** \`${f.evidence[0]}\`\n`;
        }
        md += `\n`;
      }
      const blob = new Blob([md], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pentest-report-${results.target}.md`;
      a.click();
      URL.revokeObjectURL(url);
    }
  }

  // If user is not authenticated, render Login Portal
  if (!user) {
    return <LoginView onLogin={handleLogin} />;
  }

  const isRunning = status?.overall_status === "running" || status?.overall_status === "queued";
  const currentLogs = status?.logs || results?.logs || [];
  const currentTarget = status?.target || results?.target || "scanme.nmap.org";

  // Dynamic metrics: Populated with real findings in real time
  const distribution = results
    ? results.severity_distribution
    : (status?.severity_distribution || { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  const rawFindings = results
    ? results.raw_findings
    : (status?.live_findings || []);
  const totalFindings = results
    ? results.raw_findings.length
    : (status?.findings_count || 0);
  const duplicateGroups = results
    ? (results.correlated_findings?.length ?? results.duplicate_groups ?? 0)
    : (status?.correlated_count ?? status?.duplicate_groups ?? 0);

  return (
    <div className="flex min-h-screen text-[var(--text-primary)] bg-[#080c14]">
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
        {/* Professional Enterprise Top Bar */}
        <header className="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 bg-slate-950/90 backdrop-blur-xl px-8 py-3.5">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <span className="text-slate-500">Target</span>
              <ChevronRight size={13} className="text-slate-600" />
              <span className="font-semibold text-slate-200 font-mono flex items-center gap-1.5">
                <Target size={14} className="text-blue-400" />
                {currentTarget}
              </span>
              {status?.in_scope && status.in_scope.length > 0 && (
                <span className="hidden sm:inline-flex items-center gap-1 rounded bg-slate-900 border border-slate-800 px-2 py-0.5 text-[11px] font-mono text-slate-300">
                  Scope: {status.in_scope[0]}
                </span>
              )}
              {status?.out_of_scope && status.out_of_scope.length > 0 && (
                <span className="hidden sm:inline-flex items-center gap-1 rounded bg-rose-500/10 border border-rose-500/20 px-1.5 py-0.5 text-[11px] font-mono text-rose-300 font-medium">
                  {status.out_of_scope.length} Excluded
                </span>
              )}
            </div>

            <span className="rounded border border-slate-800 bg-slate-900 px-2 py-0.5 text-[10px] font-mono text-slate-400">
              7-Engine Cluster
            </span>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-1.5 text-xs font-mono">
              <UserCheck size={13} className="text-emerald-400" />
              <span className="text-slate-200 font-semibold">{user.username}</span>
              <span className="text-slate-600">•</span>
              <span className="text-slate-400 text-[11px]">SecOps Clearance</span>
            </div>

            {isRunning && (
              <button
                onClick={() => handleCancelScan()}
                className="flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/15 hover:bg-rose-500/25 px-3 py-1.5 text-xs font-semibold text-rose-300 transition-all cursor-pointer shadow-xs"
                title="Abort and end current scan execution"
              >
                <StopCircle size={13} className="text-rose-400 animate-pulse" />
                <span>Abort Scan</span>
              </button>
            )}

            <button
              onClick={() =>
                handleStart(
                  currentTarget,
                  ["nuclei", "zap", "nikto", "whatweb", "nmap", "sslyze", "wapiti"],
                  "web"
                )
              }
              disabled={!!isRunning}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 transition-all disabled:opacity-40 cursor-pointer"
            >
              <RotateCw size={12} className={isRunning ? "animate-spin text-blue-400" : ""} />
              <span>Rescan</span>
            </button>

            {/* Export Dropdown Menu */}
            <div className="relative">
              <button
                onClick={() => setShowExportMenu(!showExportMenu)}
                disabled={!results}
                className="flex items-center gap-1.5 rounded-lg border border-blue-500/30 bg-blue-600 hover:bg-blue-500 px-3 py-1.5 text-xs font-medium text-white transition-all disabled:opacity-40 shadow-xs cursor-pointer"
              >
                <Download size={12} />
                <span>Export Report</span>
                <ChevronDown size={12} />
              </button>

              <AnimatePresence>
                {showExportMenu && (
                  <motion.div
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 4 }}
                    className="absolute right-0 mt-1.5 w-56 rounded-lg border border-slate-800 bg-slate-900/95 backdrop-blur-xl shadow-xl z-50 p-1.5 text-xs font-mono"
                  >
                    <button
                      onClick={() => handleDownloadReport("pdf")}
                      className="flex w-full items-center gap-2 rounded px-2.5 py-2 text-slate-200 hover:bg-blue-600/20 hover:text-blue-300 transition-colors cursor-pointer text-left"
                    >
                      <FileText size={13} className="text-rose-400" />
                      <div>
                        <div className="font-semibold text-slate-200">Download PDF Report</div>
                        <div className="text-[10px] text-slate-400">Executive formatted .pdf file</div>
                      </div>
                    </button>
                    <button
                      onClick={() => handleDownloadReport("print")}
                      className="flex w-full items-center gap-2 rounded px-2.5 py-2 text-slate-200 hover:bg-blue-600/20 hover:text-blue-300 transition-colors cursor-pointer text-left"
                    >
                      <Printer size={13} className="text-blue-400" />
                      <div>
                        <div className="font-semibold text-slate-200">Print / Save as PDF</div>
                        <div className="text-[10px] text-slate-400">Print-optimized vector audit view</div>
                      </div>
                    </button>
                    <div className="my-1 border-t border-slate-800" />
                    <button
                      onClick={() => handleDownloadReport("json")}
                      className="flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-slate-300 hover:bg-slate-800 transition-colors cursor-pointer text-left"
                    >
                      <Download size={12} className="text-slate-500" />
                      <span>Export Raw JSON Data</span>
                    </button>
                    <button
                      onClick={() => handleDownloadReport("markdown")}
                      className="flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-slate-300 hover:bg-slate-800 transition-colors cursor-pointer text-left"
                    >
                      <FileText size={12} className="text-slate-500" />
                      <span>Export Markdown (.md)</span>
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            <button
              onClick={handleLogout}
              title="Sign Out"
              className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-rose-500/10 hover:border-rose-500/30 px-2.5 py-1.5 text-xs text-slate-400 hover:text-rose-300 transition-colors cursor-pointer"
            >
              <LogOut size={13} />
            </button>
          </div>
        </header>

        {/* Secondary Navigation Tabs */}
        <div className="flex items-center gap-1 border-b border-slate-800/70 bg-slate-950/60 px-8 py-2 overflow-x-auto text-xs">
          {[
            { id: "overview" as NavTab, label: "Overview & ASM", icon: <Layers size={13} /> },
            { id: "topology" as NavTab, label: "API Attack Graph", icon: <GitBranch size={13} /> },
            { id: "findings" as NavTab, label: "Threats & Findings", icon: <ShieldAlert size={13} />, count: totalFindings },
            { id: "terminal" as NavTab, label: "Live Console", icon: <Terminal size={13} />, count: currentLogs.length, pulse: isRunning },
            { id: "scanners" as NavTab, label: "7-Engine Cluster", icon: <Cpu size={13} /> },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-md font-medium transition-all select-none cursor-pointer ${
                activeTab === tab.id
                  ? "bg-blue-600/15 border border-blue-500/40 text-blue-300 font-semibold shadow-xs"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/40"
              }`}
            >
              {tab.icon}
              <span>{tab.label}</span>
              {tab.count !== undefined && tab.count > 0 && (
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-rose-500/15 text-rose-300 border border-rose-500/20">
                  {tab.count}
                </span>
              )}
              {tab.pulse && <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-ping" />}
            </button>
          ))}
        </div>

        {/* Main Content Body */}
        <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col gap-6 px-6 py-6 md:px-8">
          <AnimatePresence>
            {apiState === "offline" && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-300 flex items-center justify-between"
              >
                <span>
                  <strong>Backend API Offline</strong> — API unreachable at <code className="font-mono bg-black/40 px-1 py-0.5 rounded">{API_BASE_URL}</code>.
                </span>
              </motion.div>
            )}

            {error && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="flex items-center justify-between rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-xs text-rose-300 font-mono"
              >
                <span>{typeof error === "string" ? error : JSON.stringify(error)}</span>
                <button
                  type="button"
                  onClick={() => setError(null)}
                  className="ml-3 text-rose-400 hover:text-white cursor-pointer px-1.5 py-0.5 rounded hover:bg-rose-500/20"
                  title="Dismiss alert"
                >
                  ✕
                </button>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Multiple Concurrent Scans Switcher Strip */}
          {allScans.length > 1 && (
            <div className="flex flex-wrap items-center gap-2 rounded-lg border border-slate-800/80 bg-slate-900/50 p-2 text-xs font-mono">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5 mr-1">
                <Activity size={12} className="text-blue-400" />
                Concurrent Assessments ({allScans.length}):
              </span>
              {allScans.map((s) => {
                const active = (selectedScanId || status?.scan_id) === s.scan_id;
                const isScanRunning =
                  s.overall_status === "running" || s.overall_status === "queued";
                return (
                  <button
                    key={s.scan_id}
                    onClick={() => handleSelectScan(s.scan_id)}
                    className={`flex items-center gap-2 px-2.5 py-1 rounded-md border text-xs transition-all cursor-pointer ${
                      active
                        ? "bg-blue-600/20 border-blue-500/50 text-blue-200 font-semibold shadow-xs"
                        : "bg-slate-950/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700"
                    }`}
                  >
                    <span
                      className={`h-2 w-2 rounded-full ${
                        isScanRunning
                          ? "bg-blue-400 animate-pulse"
                          : s.overall_status === "completed"
                          ? "bg-emerald-400"
                          : "bg-rose-400"
                      }`}
                    />
                    <span className="font-semibold text-slate-200 truncate max-w-[130px]">
                      {s.target}
                    </span>
                    <span className="text-[10px] text-slate-400">
                      {isScanRunning ? `${s.progress_pct}%` : s.overall_status}
                    </span>
                  </button>
                );
              })}
            </div>
          )}

          {/* TAB 1: OVERVIEW & ATTACK SURFACE MANAGEMENT */}
          {activeTab === "overview" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              {/* Executive Metrics Row */}
              <ExecutiveMetrics
                distribution={distribution}
                totalFindings={totalFindings}
                duplicateGroups={duplicateGroups}
                isScanning={!!isRunning}
                enginesCount={status?.scanners?.length ? status.scanners.length : 7}
                engineNames={status?.scanners?.length ? status.scanners.map((s) => s.tool.toUpperCase()).join(" • ") : "Nuclei • ZAP • Nikto • WhatWeb • Nmap • SSLyze • Wapiti"}
              />

              {/* Scan Launcher Card - Allows launching concurrent scans anytime */}
              <ScanForm onStart={handleStart} disabled={false} />

              {/* Wildcard Perimeter Reconnaissance Tracker */}
              <WildcardPerimeterTracker
                target={currentTarget}
                inScope={status?.in_scope}
                outOfScope={status?.out_of_scope}
                isScanning={!!isRunning}
                findingsCount={totalFindings}
              />

              {/* Live Telemetry Progress Card */}
              {status && (
                <ScannerProgressList
                  scanners={status.scanners}
                  onOpenTerminal={() => setActiveTab("terminal")}
                  terminalOpen={false}
                  onCancelScan={() => handleCancelScan()}
                  logsCount={currentLogs.length}
                  progressPct={status.progress_pct}
                  etaSeconds={status.eta_seconds}
                  elapsedSeconds={status.elapsed_seconds}
                  overallStatus={status.overall_status}
                />
              )}

              {/* Live Findings Feed: Intercepted in real time while scanning */}
              {(isRunning || (status?.live_findings && status.live_findings.length > 0) || rawFindings.length > 0) && (
                <LiveFindingsFeed
                  findings={status?.live_findings || rawFindings}
                  isScanning={!!isRunning}
                  onSelectFinding={() => setActiveTab("findings")}
                />
              )}

              {/* Asset Inventory */}
              <AssetInventoryTable
                target={currentTarget}
                findings={rawFindings}
                onTriggerScan={(endpoint) =>
                  handleStart(
                    endpoint,
                    ["nuclei", "zap", "nikto", "whatweb", "nmap", "sslyze", "wapiti"],
                    "web"
                  )
                }
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
                onTriggerScan={(endpoint) =>
                  handleStart(
                    endpoint,
                    ["nuclei", "zap", "nikto", "whatweb", "nmap", "sslyze", "wapiti"],
                    "web"
                  )
                }
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
                enginesCount={status?.scanners?.length ? status.scanners.length : 7}
                engineNames={status?.scanners?.length ? status.scanners.map((s) => s.tool.toUpperCase()).join(" • ") : "Nuclei • ZAP • Nikto • WhatWeb • Nmap • SSLyze • Wapiti"}
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
                    {totalFindings === 0 && results
                      ? "Target Verified Clean — 0 Vulnerabilities Flagged"
                      : "Awaiting Scan Execution"}
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
              {status && (
                <ScannerProgressList
                  scanners={status.scanners}
                  onCancelScan={() => handleCancelScan()}
                  overallStatus={status.overall_status}
                  progressPct={status.progress_pct}
                  etaSeconds={status.eta_seconds}
                  elapsedSeconds={status.elapsed_seconds}
                />
              )}
            </motion.div>
          )}

          {/* TAB 5: SCANNER CLUSTER */}
          {activeTab === "scanners" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-8">
              {status && (
                <ScannerProgressList
                  scanners={status.scanners}
                  onCancelScan={() => handleCancelScan()}
                  overallStatus={status.overall_status}
                  progressPct={status.progress_pct}
                  etaSeconds={status.eta_seconds}
                  elapsedSeconds={status.elapsed_seconds}
                />
              )}
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
