import type { ScannerName, ScanResultsResponse, ScanStatusResponse } from "./types";

// Backend runs via docker-compose (Celery/Redis/Postgres/real scanners don't
// fit static hosting), so a GitHub-Pages-hosted dashboard has no backend to
// reach unless you point it at one you're running. Override at build time
// with VITE_API_BASE_URL, or at runtime via ?api=<url> for a quick demo.
const runtimeOverride = new URLSearchParams(window.location.search).get("api");
export const API_BASE_URL =
  runtimeOverride || import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export class ApiUnreachableError extends Error {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      headers: { "Content-Type": "application/json" },
      ...init,
    });
  } catch {
    throw new ApiUnreachableError(`Could not reach API at ${API_BASE_URL}`);
  }
  if (!response.ok) {
    let errorMsg = `Request failed: ${response.status}`;
    try {
      const data = await response.json();
      if (typeof data.detail === "string") {
        errorMsg = data.detail;
      } else if (Array.isArray(data.detail)) {
        errorMsg = data.detail
          .map((d: any) => {
            if (typeof d === "string") return d;
            const field = Array.isArray(d.loc)
              ? d.loc.filter((l: any) => l !== "body").join(".")
              : "";
            return field ? `${field}: ${d.msg || JSON.stringify(d)}` : (d.msg || JSON.stringify(d));
          })
          .join(" | ");
      } else if (data.detail && typeof data.detail === "object") {
        errorMsg = data.detail.msg || JSON.stringify(data.detail);
      } else if (typeof data.message === "string") {
        errorMsg = data.message;
      }
    } catch {
      // response wasn't JSON
    }
    throw new Error(errorMsg);
  }
  return response.json() as Promise<T>;
}

export function startScan(
  target: string,
  scanners: ScannerName[],
  profile: string,
  in_scope?: string[],
  out_of_scope?: string[],
) {
  return request<ScanStatusResponse>("/scan/start", {
    method: "POST",
    body: JSON.stringify({ target, scanners, profile, in_scope, out_of_scope }),
  });
}

export function getScanStatus(scanId: string) {
  return request<ScanStatusResponse>(`/scan/status/${scanId}`);
}

export function getScanResults(scanId: string) {
  return request<ScanResultsResponse>(`/scan/results/${scanId}`);
}

export function getScanLogs(scanId: string) {
  return request<{ scan_id: string; logs: string[] }>(`/scan/logs/${scanId}`);
}

export function probeTarget(target: string) {
  return request<import("./types").TargetProbeResponse>("/target/probe", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
}

export async function checkApiHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/health`);
    return response.ok;
  } catch {
    return false;
  }
}

export function cancelScan(scanId: string) {
  return request<ScanStatusResponse>(`/scan/cancel/${scanId}`, {
    method: "POST",
  });
}

export async function downloadScanReportPdf(scanId: string, target: string): Promise<void> {
  const cleanTarget = target.replace(/^https?:\/\//i, "").replace(/[/:]/g, "_");
  const response = await fetch(`${API_BASE_URL}/scan/report/${scanId}/pdf`);
  if (!response.ok) {
    throw new Error(`Failed to download PDF report: ${response.statusText}`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `pentest-report-${cleanTarget}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}
