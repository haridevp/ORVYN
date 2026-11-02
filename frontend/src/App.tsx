import { useEffect, useRef, useState } from "react";
import {
  API_BASE_URL,
  ApiUnreachableError,
  checkApiHealth,
  getScanResults,
  getScanStatus,
  listScans,
  deleteScan,
  startScan,
  cancelScan,
  downloadScanReportPdf,
} from "./api";
import { openPrintablePentestReport } from "./utils/pdfExport";
import { WildcardPerimeterTracker } from "./components/WildcardPerimeterTracker";
import { LiveTerminal } from "./components/LiveTerminal";
import { ScannerProgressList } from "./components/ScannerProgressList";
import { Sidebar, type NavTab } from "./components/Sidebar";
import { ExecutiveMetrics } from "./components/ExecutiveMetrics";
import { ApiTopologyGraph } from "./components/ApiTopologyGraph";
import { AssetInventoryTable } from "./components/AssetInventoryTable";
import { ScanHistoryView } from "./components/ScanHistoryView";
import { LoginView } from "./components/LoginView";
import { LiveFindingsFeed } from "./components/LiveFindingsFeed";
import { NewPentestWizard } from "./components/NewPentestWizard";
import { IssuesView } from "./components/IssuesView";
import { DomainsView } from "./components/DomainsView";
import { KnowledgeView } from "./components/KnowledgeView";
import { CommandPalette } from "./components/CommandPalette";
import { DocumentationPortal } from "./components/DocumentationPortal";
import type { ScannerName, ScannerProgress, ScanResultsResponse, ScanStatusResponse } from "./types";
import {
  Target,
  Download,
  RotateCw,
  StopCircle,
  FileText,
  Printer,
  ChevronDown,
  Plus,
  Settings,
  LogOut,
  History,
  BookOpen,
  Activity,
  Globe,
  Play,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

type ApiState = "checking" | "online" | "offline";

const DEFAULT_STANDBY_SCANNERS: ScannerProgress[] = [
  { tool: "nmap", status: "queued", findings_count: 0 },
  { tool: "whatweb", status: "queued", findings_count: 0 },
  { tool: "sslyze", status: "queued", findings_count: 0 },
  { tool: "nikto", status: "queued", findings_count: 0 },
  { tool: "zap", status: "queued", findings_count: 0 },
  { tool: "nuclei", status: "queued", findings_count: 0 },
  { tool: "wapiti", status: "queued", findings_count: 0 },
];

export default function App() {
  // Environment check:
  // Is this running in local development (localhost / 127.0.0.1 / local test IPs)?
  const isLocalhost =
    typeof window !== "undefined" &&
    (window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1" ||
      window.location.hostname === "0.0.0.0" ||
      window.location.hostname.endsWith(".local"));

  // Default to interactive pentesting console ("app"); docs accessible via "#docs" or Docs button
  const [localViewMode, setLocalViewMode] = useState<"app" | "docs">(() => {
    if (typeof window !== "undefined" && window.location.hash === "#docs") {
      return "docs";
    }
    return "app";
  });

  // Quick Assessment Bar state (mounted on Dashboard)
  const [quickTarget, setQuickTarget] = useState("scanme.nmap.org");
  const [quickProfile, setQuickProfile] = useState("web");
  const [quickSecondary, setQuickSecondary] = useState(true);

  // Authentication State: On localhost, provide default developer session so local testing is never blocked
  const [user, setUser] = useState<{ username: string; role: string } | null>(() => {
    const saved = localStorage.getItem("pentest_user");
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        // Fallback
      }
    }
    return { username: "haridevp", role: "Security Team" };
  });

  const [apiState, setApiState] = useState<ApiState>("checking");
  const [allScans, setAllScans] = useState<ScanStatusResponse[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [results, setResults] = useState<ScanResultsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Persist activeTab across refreshes and tab switches to prevent jumping back to dashboard
  const [activeTab, setActiveTabState] = useState<NavTab>(() => {
    try {
      const saved = localStorage.getItem("orvyn_active_tab");
      const validTabs: NavTab[] = [
        "dashboard",
        "pentests",
        "issues",
        "domains",
        "topology",
        "terminal",
        "knowledge",
        "history",
        "settings",
      ];
      if (saved && validTabs.includes(saved as NavTab)) {
        return saved as NavTab;
      }
    } catch {
      // Fallback
    }
    return "dashboard";
  });

  const setActiveTab = (tab: NavTab) => {
    setActiveTabState(tab);
    try {
      localStorage.setItem("orvyn_active_tab", tab);
    } catch {
      // Ignore
    }
  };

  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showAdminMenu, setShowAdminMenu] = useState(false);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);

  const selectedScanIdRef = useRef<string | null>(null);
  const pollersRef = useRef<Map<string, number>>(new Map());

  useEffect(() => {
    selectedScanIdRef.current = selectedScanId;
  }, [selectedScanId]);

  useEffect(() => {
    checkApiHealth().then((ok) => {
      setApiState(ok ? "online" : "offline");
      if (ok) {
        listScans()
          .then((scans) => {
            setAllScans(scans);
            if (scans.length > 0 && !selectedScanIdRef.current) {
              handleSelectScan(scans[0].scan_id, scans[0]);
            }
          })
          .catch(() => {});
      }
    });
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

  function startPollingForScan(scanId: string) {
    const existingPoller = pollersRef.current.get(scanId);
    if (existingPoller) {
      window.clearInterval(existingPoller);
      pollersRef.current.delete(scanId);
    }

    let pollCount = 0;
    let consecutiveErrors = 0;
    const intervalId = window.setInterval(async () => {
      pollCount += 1;
      if (pollCount > 600) {
        window.clearInterval(intervalId);
        pollersRef.current.delete(scanId);
        return;
      }
      try {
        const next = await getScanStatus(scanId);
        consecutiveErrors = 0;
        setAllScans((prev) =>
          prev.map((s) => (s.scan_id === scanId ? next : s))
        );

        if (!selectedScanIdRef.current || selectedScanIdRef.current === scanId) {
          setStatus(next);
        }

        const anyProgress = next.scanners.some(
          (s) => s.status === "completed" || (s.findings_count ?? 0) > 0
        );
        if (anyProgress) {
          try {
            const currentResults = await getScanResults(scanId);
            if (!selectedScanIdRef.current || selectedScanIdRef.current === scanId) {
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
          pollersRef.current.delete(scanId);
          try {
            const finalResults = await getScanResults(scanId);
            if (!selectedScanIdRef.current || selectedScanIdRef.current === scanId) {
              setResults(finalResults);
            }
          } catch {
            // Ignore
          }
        }
      } catch {
        consecutiveErrors += 1;
        if (consecutiveErrors > 10) {
          window.clearInterval(intervalId);
          pollersRef.current.delete(scanId);
        }
      }
    }, 1000);

    pollersRef.current.set(scanId, intervalId);
  }

  async function handleSelectScan(scanId: string, directScan?: ScanStatusResponse) {
    setSelectedScanId(scanId);
    setResults(null);
    const existing = directScan || allScans.find((s) => s.scan_id === scanId);
    if (existing) {
      setStatus(existing);
      if (
        (existing.overall_status === "running" || existing.overall_status === "queued") &&
        !pollersRef.current.has(scanId)
      ) {
        startPollingForScan(scanId);
      }
    }
    try {
      const res = await getScanResults(scanId);
      if (!selectedScanIdRef.current || selectedScanIdRef.current === scanId) {
        setResults(res);
      }
    } catch {
      // Job may still be in initial progress
    }
  }

  async function handleDeleteScan(scanId: string) {
    try {
      await deleteScan(scanId);
      const remaining = allScans.filter((s) => s.scan_id !== scanId);
      setAllScans(remaining);
      if (selectedScanId === scanId) {
        if (remaining.length > 0) {
          handleSelectScan(remaining[0].scan_id);
        } else {
          setSelectedScanId(null);
          setStatus(null);
          setResults(null);
        }
      }
    } catch {
      // Ignore
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
    template?: string | null,
    enableSecondaryTools?: boolean,
  ) {
    setError(null);
    setResults(null);
    try {
      const initial = await startScan(
        target,
        scanners,
        profile,
        inScope,
        outOfScope,
        template,
        enableSecondaryTools
      );
      setAllScans((prev) => [initial, ...prev.filter((s) => s.scan_id !== initial.scan_id)]);
      setSelectedScanId(initial.scan_id);
      setStatus(initial);
      setActiveTab("dashboard");
      startPollingForScan(initial.scan_id);
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
      a.download = `orvyn-report-${results.target}.json`;
      a.click();
      URL.revokeObjectURL(url);
      return;
    }

    if (format === "markdown") {
      let md = `# ORVYN Executive Intelligence Report: ${results.target}\n\n`;
      md += `*Offensive Risk and Vulnerability Intelligence Network*\n\n`;
      md += `- **Generated At:** ${new Date().toUTCString()}\n`;
      md += `- **Assessment ID:** ${results.scan_id}\n`;
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
      a.download = `orvyn-report-${results.target}.md`;
      a.click();
      URL.revokeObjectURL(url);
    }
  }

  // If toggled to Docs Portal, render it with one-click return to console enabled
  if (localViewMode === "docs") {
    return (
      <DocumentationPortal
        isLocalhost={isLocalhost}
        onSwitchToConsole={() => {
          setLocalViewMode("app");
          window.location.hash = "#app";
        }}
      />
    );
  }

  // If user explicitly logged out on localhost, render Login Portal
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

  const correlatedFindings = results?.correlated_findings || [];

  return (
    <div className="flex min-h-screen text-[var(--text-primary)] bg-[#07080c]">
      {/* Command Palette (Ctrl+K shortcut) */}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        onNavigate={(tab) => setActiveTab(tab as NavTab)}
        onNewPentest={() => setActiveTab("pentests")}
      />

      {/* Sidebar Navigation (Matching Screenshot 1-4) */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        threatCount={totalFindings}
        logsCount={currentLogs.length}
        historyCount={allScans.length}
        user={user}
        onLogout={handleLogout}
        onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
        onOpenDocs={() => {
          setLocalViewMode("docs");
          window.location.hash = "#docs";
        }}
      />

      <div className="min-w-0 flex-1 relative flex flex-col">
        {/* Minimal Enterprise Top Bar */}
        <header className="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-4 border-b border-neutral-800/80 bg-[#07080c]/90 backdrop-blur-xl px-6 py-3">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => {
                setLocalViewMode("docs");
                window.location.hash = "#docs";
              }}
              className="flex items-center gap-1.5 rounded-lg border border-neutral-800 bg-neutral-900/60 hover:bg-neutral-800 px-3 py-1.5 text-xs text-neutral-300 transition-colors cursor-pointer"
              title="Documentation Portal"
            >
              <BookOpen size={13} className="text-neutral-400" />
              <span>Docs</span>
            </button>

            <div className="flex items-center gap-2 rounded-lg bg-neutral-900 border border-neutral-800 px-3 py-1.5 text-xs font-mono text-neutral-300">
              <Target size={13} className="text-neutral-400" />
              <span className="font-semibold text-white">{currentTarget}</span>
              {status?.profile && (
                <span className="text-[10px] text-neutral-500 uppercase tracking-wide">({status.profile})</span>
              )}
            </div>

            {isRunning ? (
              <div className="flex items-center gap-1.5 rounded-full bg-amber-500/10 border border-amber-500/20 px-2.5 py-1 text-xs text-amber-300 font-mono">
                <Activity size={12} className="animate-spin text-amber-400" />
                <span>Assessing ({status?.current_phase || "Active"})</span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 text-xs text-emerald-400 font-mono">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                <span>Engine Ready</span>
              </div>
            )}
          </div>

          <div className="flex items-center gap-2.5">
            {/* New Pentest Button */}
            <button
              onClick={() => setActiveTab("pentests")}
              className="flex items-center gap-1.5 rounded-lg bg-white hover:bg-neutral-200 px-3.5 py-1.5 text-xs font-semibold text-black transition-colors cursor-pointer shadow-sm"
            >
              <Plus size={13} />
              <span>New Pentest</span>
            </button>

            {isRunning && (
              <button
                onClick={() => handleCancelScan()}
                className="flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/15 hover:bg-rose-500/25 px-3 py-1.5 text-xs font-medium text-rose-300 transition-colors cursor-pointer"
                title="Abort active assessment"
              >
                <StopCircle size={13} className="text-rose-400" />
                <span>Abort</span>
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
              className="flex items-center gap-1.5 rounded-lg border border-neutral-800 bg-neutral-900/80 hover:bg-neutral-800 px-3 py-1.5 text-xs font-medium text-neutral-200 transition-colors disabled:opacity-40 cursor-pointer"
            >
              <RotateCw size={12} className={isRunning ? "animate-spin text-neutral-400" : ""} />
              <span>Rescan</span>
            </button>

            {/* Export Dropdown Menu */}
            <div className="relative">
              <button
                onClick={() => setShowExportMenu(!showExportMenu)}
                disabled={!results}
                className="flex items-center gap-1.5 rounded-full border border-neutral-800 bg-neutral-900/80 hover:bg-neutral-800 px-3.5 py-1.5 text-xs font-medium text-neutral-200 transition-all disabled:opacity-40 cursor-pointer"
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
                    className="absolute right-0 mt-1.5 w-56 rounded-xl border border-neutral-800 bg-[#0c0d12] shadow-2xl z-50 p-1.5 text-xs font-mono"
                  >
                    <button
                      onClick={() => handleDownloadReport("pdf")}
                      className="flex w-full items-center gap-2 rounded px-2.5 py-2 text-neutral-200 hover:bg-neutral-800 transition-colors cursor-pointer text-left"
                    >
                      <FileText size={13} className="text-rose-400" />
                      <div>
                        <div className="font-semibold text-white">Download PDF Report</div>
                        <div className="text-[10px] text-neutral-500">Executive formatted .pdf file</div>
                      </div>
                    </button>
                    <button
                      onClick={() => handleDownloadReport("print")}
                      className="flex w-full items-center gap-2 rounded px-2.5 py-2 text-neutral-200 hover:bg-neutral-800 transition-colors cursor-pointer text-left"
                    >
                      <Printer size={13} className="text-cyan-400" />
                      <div>
                        <div className="font-semibold text-white">Print / Save as PDF</div>
                        <div className="text-[10px] text-neutral-500">Print-optimized vector audit view</div>
                      </div>
                    </button>
                    <div className="my-1 border-t border-neutral-800" />
                    <button
                      onClick={() => handleDownloadReport("json")}
                      className="flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-neutral-300 hover:bg-neutral-800 transition-colors cursor-pointer text-left"
                    >
                      <Download size={12} className="text-neutral-500" />
                      <span>Export Raw JSON Data</span>
                    </button>
                    <button
                      onClick={() => handleDownloadReport("markdown")}
                      className="flex w-full items-center gap-2 rounded px-2.5 py-1.5 text-neutral-300 hover:bg-neutral-800 transition-colors cursor-pointer text-left"
                    >
                      <FileText size={12} className="text-neutral-500" />
                      <span>Export Markdown (.md)</span>
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Admin Profile Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setShowAdminMenu((prev) => !prev)}
                className="flex items-center gap-2 rounded-full border border-neutral-800 bg-neutral-900/80 hover:bg-neutral-800 px-3 py-1.5 text-xs text-neutral-200 transition-all cursor-pointer shadow-xs"
                title="Account & Admin Menu"
              >
                <div className="h-5 w-5 rounded-full bg-purple-500/20 border border-purple-500/40 flex items-center justify-center font-bold text-purple-300 text-[10px] font-mono">
                  {(user?.username || "A").charAt(0).toUpperCase()}
                </div>
                <span className="font-semibold text-white capitalize">{user?.username || "admin"}</span>
                <ChevronDown size={12} className={`text-neutral-400 transition-transform ${showAdminMenu ? "rotate-180" : ""}`} />
              </button>

              <AnimatePresence>
                {showAdminMenu && (
                  <motion.div
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 4 }}
                    className="absolute right-0 mt-1.5 w-60 rounded-xl border border-neutral-800 bg-[#0c0d12] shadow-2xl z-50 p-2 space-y-2 text-xs"
                  >
                    <div className="p-2.5 rounded-lg bg-neutral-900/80 border border-neutral-800">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white capitalize">{user?.username || "admin"}</span>
                        <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[9px] font-mono font-semibold">Active</span>
                      </div>
                      <div className="text-[10px] text-neutral-400 mt-0.5">{user?.role || "SecOps Lead (Admin)"}</div>
                      <div className="text-[9px] text-neutral-500 font-mono mt-0.5">{(user?.username || "admin")}@secops.io</div>
                    </div>
                    <div className="space-y-0.5 border-t border-neutral-800 pt-1">
                      <button
                        type="button"
                        onClick={() => {
                          setActiveTab("settings");
                          setShowAdminMenu(false);
                        }}
                        className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-neutral-300 hover:bg-neutral-800 hover:text-white transition-colors cursor-pointer text-left"
                      >
                        <Settings size={13} className="text-neutral-400" />
                        <span>Platform Settings</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setActiveTab("history");
                          setShowAdminMenu(false);
                        }}
                        className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-neutral-300 hover:bg-neutral-800 hover:text-white transition-colors cursor-pointer text-left"
                      >
                        <History size={13} className="text-neutral-400" />
                        <span>Scan History</span>
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setShowAdminMenu(false);
                          handleLogout();
                        }}
                        className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-rose-400 hover:bg-rose-500/10 transition-colors cursor-pointer text-left font-medium"
                      >
                        <LogOut size={13} />
                        <span>Sign Out</span>
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </header>

        {/* Main Content Body */}
        <main className="mx-auto flex w-full max-w-7xl flex-1 flex-col gap-6 px-6 py-6 md:px-8">
          <AnimatePresence>
            {apiState === "offline" && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-2.5 text-xs text-rose-300 flex items-center justify-between"
              >
                <span>
                  <strong>Backend API Offline</strong> — Running in offline/demo mode at <code className="font-mono bg-black/40 px-1 py-0.5 rounded">{API_BASE_URL}</code>.
                </span>
              </motion.div>
            )}

            {error && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="flex items-center justify-between rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-xs text-rose-300 font-mono"
              >
                <span>{typeof error === "string" ? error : JSON.stringify(error)}</span>
                <button
                  type="button"
                  onClick={() => setError(null)}
                  className="ml-3 text-rose-400 hover:text-white cursor-pointer px-1.5 py-0.5 rounded hover:bg-rose-500/20"
                >
                  ✕
                </button>
              </motion.div>
            )}
          </AnimatePresence>

          {/* VIEW 1: PENTESTS WIZARD (Matching Strix AI Screenshot 1 & 5) */}
          {activeTab === "pentests" && (
            <NewPentestWizard
              onStart={handleStart}
              isScanning={!!isRunning}
              onCancel={() => setActiveTab("dashboard")}
            />
          )}

          {/* VIEW 2: ISSUES & RAG VERDICTS (Matching Strix AI Screenshot 2) */}
          {activeTab === "issues" && (
            <IssuesView
              findings={correlatedFindings}
              distribution={distribution}
              onNewPentest={() => setActiveTab("pentests")}
            />
          )}

          {/* VIEW 4: DOMAINS & APIS (Matching Strix AI Screenshot 3) */}
          {activeTab === "domains" && (
            <DomainsView
              currentTarget={currentTarget}
              onSelectDomainForScan={(domain) => {
                handleStart(
                  domain,
                  ["nuclei", "zap", "nikto", "whatweb", "nmap", "sslyze", "wapiti"],
                  "web"
                );
              }}
            />
          )}

          {/* VIEW 5: KNOWLEDGE BASE 5,000+ CHUNKS (Matching Strix AI Screenshot 4) */}
          {activeTab === "knowledge" && (
            <KnowledgeView />
          )}

          {/* VIEW 6: DASHBOARD & EXECUTIVE OVERVIEW */}
          {activeTab === "dashboard" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              {/* Quick Assessment Launch Bar */}
              <div className="rounded-xl border border-neutral-800 bg-[#0c0d12] p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <div className="flex h-5 w-5 items-center justify-center rounded bg-neutral-800 text-neutral-300">
                      <Target size={12} />
                    </div>
                    <span className="text-xs font-semibold text-white">Target Assessment & Perimeter Recon</span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-neutral-400 font-mono">
                    <span className="flex items-center gap-1 text-emerald-400">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                      72 MCP Tools Active
                    </span>
                    <span>•</span>
                    <span>Docker Container Mode</span>
                  </div>
                </div>

                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (!quickTarget.trim() || isRunning) return;
                    handleStart(
                      quickTarget.trim(),
                      ["nuclei", "zap", "nikto", "whatweb", "nmap", "sslyze", "wapiti"],
                      quickProfile,
                      [quickTarget.trim()],
                      [],
                      null,
                      quickSecondary
                    );
                  }}
                  className="flex flex-col sm:flex-row items-stretch gap-2.5"
                >
                  <div className="relative flex-1">
                    <Globe size={14} className="absolute left-3 top-3 text-neutral-500" />
                    <input
                      type="text"
                      value={quickTarget}
                      onChange={(e) => setQuickTarget(e.target.value)}
                      placeholder="e.g. scanme.nmap.org, 192.168.1.1, or target.com"
                      className="w-full rounded-lg border border-neutral-700/80 bg-black/60 pl-9 pr-3 py-2 text-xs text-white placeholder-neutral-500 focus:border-neutral-400 focus:outline-none font-mono"
                    />
                  </div>

                  <select
                    value={quickProfile}
                    onChange={(e) => setQuickProfile(e.target.value)}
                    className="rounded-lg border border-neutral-700/80 bg-neutral-900 px-3 py-2 text-xs text-neutral-200 focus:border-neutral-400 focus:outline-none font-mono cursor-pointer"
                  >
                    <option value="recon">Recon Profile (~20s quick)</option>
                    <option value="web">Web App Profile (~45-60s)</option>
                    <option value="full">Comprehensive Full (~2m)</option>
                    <option value="deep">Deep Multi-Tool Audit (~5m)</option>
                  </select>

                  <button
                    type="submit"
                    disabled={!!isRunning || !quickTarget.trim()}
                    className="flex items-center justify-center gap-2 rounded-lg bg-white hover:bg-neutral-200 disabled:opacity-50 px-5 py-2 text-xs font-semibold text-black transition-all cursor-pointer whitespace-nowrap shadow-sm"
                  >
                    {isRunning ? (
                      <>
                        <RotateCw size={13} className="animate-spin text-black" />
                        <span>Assessing...</span>
                      </>
                    ) : (
                      <>
                        <Play size={13} fill="currentColor" />
                        <span>Launch Assessment</span>
                      </>
                    )}
                  </button>
                </form>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-1 text-[11px] text-neutral-400">
                  <label className="flex items-center gap-1.5 cursor-pointer hover:text-neutral-300">
                    <input
                      type="checkbox"
                      checked={quickSecondary}
                      onChange={(e) => setQuickSecondary(e.target.checked)}
                      className="rounded border-neutral-700 bg-neutral-900 text-white focus:ring-0 cursor-pointer h-3.5 w-3.5"
                    />
                    <span>Auto-trigger secondary tools (SQLMap, Ffuf, Wapiti) on perimeter findings</span>
                  </label>
                  <button
                    type="button"
                    onClick={() => setActiveTab("pentests")}
                    className="text-neutral-400 hover:text-white transition-colors cursor-pointer underline underline-offset-2"
                  >
                    Advanced Scope & Template Options →
                  </button>
                </div>
              </div>

              <ExecutiveMetrics
                distribution={distribution}
                totalFindings={totalFindings}
                duplicateGroups={duplicateGroups}
                isScanning={!!isRunning}
                enginesCount={status?.scanners?.length ? status.scanners.length : 7}
                engineNames={status?.scanners?.length ? status.scanners.map((s) => s.tool.toUpperCase()).join(" • ") : "Nuclei • ZAP • Nikto • WhatWeb • Nmap • SSLyze • Wapiti"}
              />

              {/* Live Telemetry Progress Card & Interactive Recon Pipeline (Always Mounted) */}
              <ScannerProgressList
                scanners={status?.scanners || DEFAULT_STANDBY_SCANNERS}
                onOpenTerminal={() => setActiveTab("terminal")}
                terminalOpen={false}
                onCancelScan={() => handleCancelScan()}
                logsCount={currentLogs.length}
                progressPct={status?.progress_pct ?? 0}
                etaSeconds={status?.eta_seconds ?? null}
                elapsedSeconds={status?.elapsed_seconds ?? 0}
                overallStatus={status?.overall_status || "idle"}
                currentPhase={status?.current_phase || "initial_scanning"}
                llmDecision={status?.llm_decision}
                ragComparison={status?.rag_comparison_summary}
                liveFindings={status?.live_findings || rawFindings}
                allLogs={currentLogs}
                target={currentTarget}
              />

              {/* Live Findings Feed */}
              {(isRunning || (status?.live_findings && status.live_findings.length > 0) || rawFindings.length > 0) && (
                <LiveFindingsFeed
                  findings={status?.live_findings || rawFindings}
                  isScanning={!!isRunning}
                  onSelectFinding={() => setActiveTab("issues")}
                />
              )}

              {/* Wildcard Reconnaissance Tracker */}
              <WildcardPerimeterTracker
                target={currentTarget}
                inScope={status?.in_scope}
                outOfScope={status?.out_of_scope}
                isScanning={!!isRunning}
                findingsCount={totalFindings}
              />

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

          {/* VIEW 7: API ATTACK GRAPH (TOPOLOGY) */}
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

          {/* VIEW 8: LIVE SCANNER CONSOLE */}
          {activeTab === "terminal" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              <LiveTerminal
                logs={currentLogs}
                isRunning={!!isRunning}
                isOpen={true}
                onToggle={() => {}}
              />
              <ScannerProgressList
                scanners={status?.scanners || DEFAULT_STANDBY_SCANNERS}
                onCancelScan={() => handleCancelScan()}
                overallStatus={status?.overall_status || "idle"}
                progressPct={status?.progress_pct ?? 0}
                etaSeconds={status?.eta_seconds ?? null}
                elapsedSeconds={status?.elapsed_seconds ?? 0}
                currentPhase={status?.current_phase || "initial_scanning"}
                llmDecision={status?.llm_decision}
                ragComparison={status?.rag_comparison_summary}
                liveFindings={status?.live_findings || rawFindings}
                allLogs={currentLogs}
                target={currentTarget}
              />
            </motion.div>
          )}

          {/* VIEW 9: SCAN HISTORY */}
          {activeTab === "history" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <ScanHistoryView
                scans={allScans}
                selectedScanId={selectedScanId}
                onSelectScan={handleSelectScan}
                onDeleteScan={handleDeleteScan}
                onNavigateToOverview={() => setActiveTab("dashboard")}
                onNewScanClick={() => setActiveTab("pentests")}
              />
            </motion.div>
          )}

          {/* VIEW 10: SETTINGS & CLUSTER STATUS */}
          {activeTab === "settings" && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
              <div className="rounded-2xl border border-neutral-800 bg-[#0c0d12] p-6 space-y-4">
                <h2 className="text-base font-bold text-white tracking-wide">
                  Security Engine Cluster Configuration
                </h2>
                <p className="text-xs text-neutral-400">
                  Manage installed penetration testing engines, MCP bridges, and local LLM judicial integrations.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs font-mono">
                  {[
                    { name: "Nuclei v3", status: "Active Engine", type: "Template DAST" },
                    { name: "OWASP ZAP", status: "Active Engine", type: "Web Proxy / Spider" },
                    { name: "Nikto 2.5", status: "Active Engine", type: "Server Scanner" },
                    { name: "WhatWeb", status: "Active Engine", type: "Tech Fingerprint" },
                    { name: "Nmap NSE", status: "Active Engine", type: "Network Recon" },
                    { name: "SSLyze", status: "Active Engine", type: "Cryptographic Audit" },
                    { name: "Wapiti", status: "Active Engine", type: "Web Vulnerabilities" },
                    { name: "SQLMap", status: "Secondary Tool", type: "SQL Injection" },
                    { name: "FFUF", status: "Secondary Tool", type: "Fuzzing & Paths" },
                  ].map((eng) => (
                    <div key={eng.name} className="p-3 rounded-xl border border-neutral-800 bg-neutral-900/60 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white">{eng.name}</span>
                        <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                      </div>
                      <div className="text-[10px] text-neutral-400">{eng.type}</div>
                      <div className="text-[10px] text-emerald-400 font-bold">{eng.status}</div>
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          )}
        </main>
      </div>
    </div>
  );
}
