import { useEffect, useRef, useState } from "react";
import { API_BASE_URL, ApiUnreachableError, checkApiHealth, getScanResults, getScanStatus, startScan } from "./api";
import { CorrelatedFindingsTable } from "./components/CorrelatedFindingsTable";
import { RawFindingsPanel } from "./components/RawFindingsPanel";
import { ScanForm } from "./components/ScanForm";
import { ScannerProgressList } from "./components/ScannerProgressList";
import { SeverityDistributionChart } from "./components/SeverityDistributionChart";
import { DEMO_RESULTS, DEMO_STATUS } from "./demoData";
import type { ScannerName, ScanResultsResponse, ScanStatusResponse } from "./types";

type ApiState = "checking" | "online" | "offline";

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

  return (
    <div className="mx-auto max-w-5xl px-4 py-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold">Multi-Scanner Vulnerability Dashboard</h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          Orchestrates Nuclei, OWASP ZAP, and Nikto, then correlates findings across tools before
          AI triage.
        </p>
      </header>

      {isDemoMode && (
        <div className="mb-6 rounded-lg border border-[var(--status-warning)]/40 bg-[var(--status-warning)]/10 px-4 py-3 text-sm">
          <strong>Demo data</strong> — no backend reachable at{" "}
          <code className="font-mono">{API_BASE_URL}</code>. Run the API via{" "}
          <code className="font-mono">docker compose up</code> and reload, or pass{" "}
          <code className="font-mono">?api=http://your-host:8000</code> in the URL.
        </div>
      )}

      {error && (
        <div className="mb-6 rounded-lg border border-[var(--status-critical)]/40 bg-[var(--status-critical)]/10 px-4 py-3 text-sm text-[var(--status-critical)]">
          {error}
        </div>
      )}

      <div className="mb-6">
        <ScanForm onStart={handleStart} disabled={isDemoMode || !!isRunning} />
      </div>

      {status && (
        <div className="mb-6">
          <ScannerProgressList scanners={status.scanners} />
        </div>
      )}

      {results && (
        <div className="flex flex-col gap-6">
          <SeverityDistributionChart distribution={results.severity_distribution} />
          <CorrelatedFindingsTable findings={results.correlated_findings} />
          <RawFindingsPanel findings={results.raw_findings} />
        </div>
      )}
    </div>
  );
}
