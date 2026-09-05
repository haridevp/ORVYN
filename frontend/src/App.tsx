import { useEffect, useRef, useState } from "react";
import { API_BASE_URL, ApiUnreachableError, checkApiHealth, getScanResults, getScanStatus, startScan } from "./api";
import { CorrelatedFindingsTable } from "./components/CorrelatedFindingsTable";
import { RawFindingsPanel } from "./components/RawFindingsPanel";
import { ScanForm } from "./components/ScanForm";
import { ScannerProgressList } from "./components/ScannerProgressList";
import { SeverityBreakdownCard } from "./components/SeverityBreakdownCard";
import { Sidebar } from "./components/Sidebar";
import { StatRow } from "./components/StatRow";
import { DEMO_RESULTS, DEMO_STATUS } from "./demoData";
import type { ScannerName, ScanResultsResponse, ScanStatusResponse } from "./types";

type ApiState = "checking" | "online" | "offline";

const STATUS_LABEL: Record<string, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  error: "Error",
};

export default function App() {
  const [apiState, setApiState] = useState<ApiState>("checking");
  const [status, setStatus] = useState<ScanStatusResponse | null>(null);
  const [results, setResults] = useState<ScanResultsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    checkApiHealth().then((ok) => setApiState(ok ? "online" : "offline"));
  }, []);

  useEffect(() => {
    if (apiState === "offline") {
      setStatus(DEMO_STATUS);
      setResults(DEMO_RESULTS);
    }
  }, [apiState]);

  useEffect(() => {
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, []);

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
          if (next.overall_status === "completed" || next.overall_status === "error") {
            if (pollRef.current) window.clearInterval(pollRef.current);
            const finalResults = await getScanResults(initial.scan_id);
            setResults(finalResults);
          }
        } catch (err) {
          if (pollRef.current) window.clearInterval(pollRef.current);
          setError(err instanceof Error ? err.message : "Polling failed");
        }
      }, 800);
    } catch (err) {
      setError(err instanceof ApiUnreachableError ? err.message : (err as Error).message);
    }
  }

  const isDemoMode = apiState === "offline";
  const isRunning = status?.overall_status === "running" || status?.overall_status === "queued";

  const criticalHigh = results
    ? results.severity_distribution.critical + results.severity_distribution.high
    : 0;
  const totalFindings = results ? results.raw_findings.length : 0;

  return (
    <div className="flex min-h-screen bg-[var(--surface-page)]">
      <Sidebar />

      <div className="min-w-0 flex-1">
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] bg-[var(--surface-1)] px-6 py-5">
          <div>
            <h1 className="text-lg font-semibold text-[var(--text-primary)]">Security Dashboard</h1>
            <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
              Orchestrates Nuclei, OWASP ZAP, and Nikto, then correlates findings across tools
              before AI triage.
            </p>
          </div>
          {status && (
            <div className="text-right">
              <p className="text-xs text-[var(--text-muted)]">Target</p>
              <p className="font-mono text-sm text-[var(--text-primary)]">{status.target}</p>
            </div>
          )}
        </header>

        <main className="mx-auto flex max-w-6xl flex-col gap-6 px-6 py-6">
          {isDemoMode && (
            <div className="rounded-lg border border-[var(--status-warning)]/40 bg-[var(--status-warning)]/10 px-4 py-3 text-sm">
              <strong>Demo data</strong> — no backend reachable at{" "}
              <code className="font-mono">{API_BASE_URL}</code>. Run the API via{" "}
              <code className="font-mono">docker compose up</code> and reload, or pass{" "}
              <code className="font-mono">?api=http://your-host:8000</code> in the URL.
            </div>
          )}

          {error && (
            <div className="rounded-lg border border-[var(--status-critical)]/40 bg-[var(--status-critical)]/10 px-4 py-3 text-sm text-[var(--status-critical)]">
              {error}
            </div>
          )}

          <ScanForm onStart={handleStart} disabled={isDemoMode || !!isRunning} />

          {status && (
            <StatRow
              stats={[
                { label: "Overall Status", value: STATUS_LABEL[status.overall_status] },
                { label: "Total Findings", value: totalFindings },
                {
                  label: "Critical + High",
                  value: criticalHigh,
                  note: criticalHigh > 0 ? "needs attention" : undefined,
                  noteColor: "var(--status-critical)",
                },
                { label: "Duplicate Groups", value: results?.duplicate_groups ?? 0 },
                { label: "Scanners Run", value: status.scanners.length },
              ]}
            />
          )}

          {status && <ScannerProgressList scanners={status.scanners} />}

          {results && (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
              <div className="lg:col-span-2">
                <CorrelatedFindingsTable findings={results.correlated_findings} />
              </div>
              <SeverityBreakdownCard distribution={results.severity_distribution} />
            </div>
          )}

          {results && <RawFindingsPanel findings={results.raw_findings} />}
        </main>
      </div>
    </div>
  );
}
