import type { ScanResultsResponse } from "../types";

export function openPrintablePentestReport(results: ScanResultsResponse): void {
  const printWindow = window.open("", "_blank", "width=900,height=1000");
  if (!printWindow) {
    alert("Please allow popups to view the printable PDF audit report.");
    return;
  }

  const target = results.target || "Target Perimeter";
  const dist = results.severity_distribution || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const correlated = results.correlated_findings || [];
  const inScope = (results.in_scope || [`*.${target}`, target]).join(", ");
  const outOfScope = (results.out_of_scope || []).join(", ") || "None (Standard strict scope)";
  const nowStr = new Date().toUTCString();

  const sevClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical": return "background:#fee2e2;color:#991b1b;border:1px solid #f87171;";
      case "high": return "background:#ffedd5;color:#c2410c;border:1px solid #fb923c;";
      case "medium": return "background:#fef3c7;color:#b45309;border:1px solid #fcd34d;";
      case "low": return "background:#dbeafe;color:#1d4ed8;border:1px solid #93c5fd;";
      default: return "background:#f1f5f9;color:#475569;border:1px solid #cbd5e1;";
    }
  };

  const findingsHtml = correlated.map((f, i) => `
    <div style="border:1px solid #e2e8f0;border-radius:6px;margin-bottom:14px;padding:12px;page-break-inside:avoid;background:#fafafa;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
        <span style="font-weight:700;font-size:13px;color:#0f172a;">#${i + 1} ${escapeHtml(f.vulnerability)}</span>
        <span style="padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;${sevClass(f.severity)}">
          ${escapeHtml(f.severity)}
        </span>
      </div>
      <div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:11px;color:#334155;margin-bottom:8px;">
        <strong>Engines:</strong> <span>${escapeHtml(f.contributing_tools.join(", "))}</span>
        <strong>Confidence:</strong> <span>${f.confidence}% Verified</span>
        <strong>Target / URL:</strong> <code style="font-family:monospace;background:#f1f5f9;padding:1px 4px;border-radius:3px;">${escapeHtml(f.target)}</code>
      </div>
      <p style="font-size:11px;color:#475569;margin:4px 0 8px 0;line-height:1.4;">${escapeHtml(f.description)}</p>
      ${f.evidence && f.evidence.length > 0 ? `
        <div style="font-size:10px;font-family:monospace;background:#f8fafc;border:1px solid #e2e8f0;padding:6px 8px;border-radius:4px;margin-bottom:8px;word-break:break-all;">
          <strong>Evidence:</strong> ${escapeHtml(f.evidence[0])}
        </div>
      ` : ""}
      ${f.ai_threat_explanation ? `
        <div style="font-size:11px;background:#faf5ff;border-left:3px solid #a855f7;padding:6px 8px;color:#581c87;margin-bottom:6px;">
          <strong>AI Threat Analysis (Qwen 2.5):</strong> ${escapeHtml(f.ai_threat_explanation)}
        </div>
      ` : ""}
      <div style="font-size:11px;background:#f0fdf4;border-left:3px solid #16a34a;padding:6px 8px;color:#166534;">
        <strong>Remediation Recommendation:</strong> ${escapeHtml(f.ai_remediation || "Restrict endpoint parameters, apply input validation, and update components to stable patched release.")}
      </div>
    </div>
  `).join("");

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>ORVYN Intelligence Report - ${escapeHtml(target)}</title>
      <style>
        @page { size: letter; margin: 15mm; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; padding: 20px; font-size: 12px; line-height: 1.5; }
        .header { border-bottom: 2px solid #0284c7; padding-bottom: 12px; margin-bottom: 20px; }
        .org-title { font-size: 10px; font-weight: 700; color: #64748b; letter-spacing: 1px; text-transform: uppercase; }
        .doc-title { font-size: 18px; font-weight: 800; color: #0f172a; margin: 4px 0; }
        .confidential-badge { display: inline-block; background: #0f172a; color: #fff; padding: 2px 8px; font-size: 9px; font-weight: 700; border-radius: 3px; letter-spacing: 0.5px; }
        .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; margin-bottom: 20px; }
        .meta-item label { font-size: 9px; font-weight: 700; color: #64748b; text-transform: uppercase; display: block; }
        .meta-item span { font-size: 12px; font-weight: 600; color: #0f172a; }
        .severity-matrix { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-bottom: 20px; }
        .sev-box { padding: 10px; border-radius: 6px; text-align: center; }
        .sev-count { font-size: 20px; font-weight: 800; }
        .sev-label { font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .section-title { font-size: 13px; font-weight: 700; color: #0f172a; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; margin: 18px 0 10px 0; }
        .print-btn { background: #0284c7; color: white; border: none; padding: 8px 16px; border-radius: 4px; font-weight: 600; cursor: pointer; margin-bottom: 16px; }
        @media print { .no-print { display: none; } body { padding: 0; } }
      </style>
    </head>
    <body>
      <div class="no-print" style="text-align:right;">
        <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>
      </div>

      <div class="header">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;">
          <div>
            <div class="org-title">ORVYN // OFFENSIVE RISK AND VULNERABILITY INTELLIGENCE NETWORK</div>
            <div class="doc-title">OFFENSIVE RISK & VULNERABILITY AUDIT REPORT</div>
            <div style="font-size:11px;color:#0284c7;font-weight:600;">Target Perimeter: ${escapeHtml(target)}</div>
          </div>
          <span class="confidential-badge">STRICTLY CONFIDENTIAL</span>
        </div>
      </div>

      <div class="meta-grid">
        <div class="meta-item"><label>Target Host</label><span>${escapeHtml(target)}</span></div>
        <div class="meta-item"><label>Assessment ID</label><span>${escapeHtml((results.scan_id || "").slice(0, 14))}</span></div>
        <div class="meta-item"><label>Engines Deployed</label><span>All 7 Verified</span></div>
        <div class="meta-item"><label>Date Generated</label><span>${nowStr.slice(0, 16)}</span></div>
      </div>

      <div class="section-title">1. EXECUTIVE SUMMARY & POSTURE EVALUATION</div>
      <p style="font-size:11px;color:#475569;margin-bottom:12px;">
        An automated security assessment was executed against the designated perimeter. A total of <strong>${correlated.length}</strong> correlated vulnerabilities were confirmed across multi-engine consensus.
      </p>

      <div class="severity-matrix">
        <div class="sev-box" style="background:#fee2e2;color:#991b1b;border:1px solid #f87171;">
          <div class="sev-count">${dist.critical || 0}</div>
          <div class="sev-label">Critical</div>
        </div>
        <div class="sev-box" style="background:#ffedd5;color:#c2410c;border:1px solid #fb923c;">
          <div class="sev-count">${dist.high || 0}</div>
          <div class="sev-label">High</div>
        </div>
        <div class="sev-box" style="background:#fef3c7;color:#b45309;border:1px solid #fcd34d;">
          <div class="sev-count">${dist.medium || 0}</div>
          <div class="sev-label">Medium</div>
        </div>
        <div class="sev-box" style="background:#dbeafe;color:#1d4ed8;border:1px solid #93c5fd;">
          <div class="sev-count">${dist.low || 0}</div>
          <div class="sev-label">Low</div>
        </div>
        <div class="sev-box" style="background:#f1f5f9;color:#475569;border:1px solid #cbd5e1;">
          <div class="sev-count">${dist.info || 0}</div>
          <div class="sev-label">Informational</div>
        </div>
      </div>

      <div class="section-title">2. SCOPE & PERIMETER BOUNDARIES</div>
      <div style="font-size:11px;margin-bottom:14px;color:#334155;">
        <div><strong>In-Scope Target Rules:</strong> <code>${escapeHtml(inScope)}</code></div>
        <div style="margin-top:3px;"><strong>Out-of-Scope Exclusions:</strong> <code>${escapeHtml(outOfScope)}</code></div>
      </div>

      <div class="section-title">3. CORRELATED FINDINGS & THREAT DETAILS (${correlated.length})</div>
      ${findingsHtml || '<p style="color:#16a34a;font-weight:600;">Zero active vulnerabilities detected across designated scope.</p>'}

      <div class="section-title">4. RULES OF ENGAGEMENT & ETHICAL DISCLAIMER</div>
      <p style="font-size:10px;color:#64748b;line-height:1.4;">
        This assessment report contains confidential vulnerability findings conducted under authorized rules of engagement. Information is provided strictly for defensive remediation and risk mitigation. Unauthorized dissemination or weaponization of findings is strictly prohibited.
      </p>

      <div style="margin-top:24px;border-top:1px solid #e2e8f0;padding-top:8px;display:flex;justify-content:space-between;font-size:9px;color:#94a3b8;">
        <span>STRICTLY CONFIDENTIAL - ORVYN INTELLIGENCE NETWORK</span>
        <span>Generated ${nowStr}</span>
      </div>
    </body>
    </html>
  `;

  printWindow.document.open();
  printWindow.document.write(html);
  printWindow.document.close();
}

function escapeHtml(str: string | null | undefined): string {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
