"""
Deterministic findings repository for all 7 scanners.

Provides:
1. Targeted correlation demo findings for test / demo suites (*.local / demo targets).
2. Comprehensive 50+ findings from `standardized_scan_results.json` for targets
   like scanme.sh / scanme.nmap.org / custom perimeters.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from references import enrich_reference
from schemas import ScannerFinding, ScannerName, Severity

SEVERITY_CONV = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
}

TOOL_MAP = {
    "nuclei": ScannerName.nuclei,
    "zap": ScannerName.zap,
    "owasp zap": ScannerName.zap,
    "nikto": ScannerName.nikto,
    "whatweb": ScannerName.whatweb,
    "nmap": ScannerName.nmap,
    "sslyze": ScannerName.sslyze,
    "wapiti": ScannerName.wapiti,
}


def _find_standardized_json() -> Path | None:
    candidates = [
        Path(__file__).parent / "standardized_scan_results.json",
        Path(__file__).parents[1] / "standardized_scan_results.json",
        Path(__file__).parents[3] / "vuln_scanner_project" / "standardized_scan_results.json",
        Path("src/backend/scanners/standardized_scan_results.json"),
        Path("vuln_scanner_project/standardized_scan_results.json"),
        Path("standardized_scan_results.json"),
    ]
    for c in candidates:
        try:
            if c.is_file() and c.stat().st_size > 0:
                return c
        except Exception:
            continue
    return None


def _load_standardized_data() -> list[dict[str, Any]]:
    path = _find_standardized_json()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


# Cache loaded data
_CACHED_DATA: list[dict[str, Any]] | None = None


def get_all_dataset() -> list[dict[str, Any]]:
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = _load_standardized_data()
    return _CACHED_DATA


# ---------------------------------------------------------------------------
# Test Suite Demo Findings (for *.local and demo targets)
# ---------------------------------------------------------------------------
def demo_nuclei_findings(target: str) -> list[dict]:
    return [
        {
            "vulnerability": "SQL Injection",
            "severity": Severity.medium,
            "description": "A parameter reflected in a database query appears to accept unescaped input.",
            "evidence": f"GET {target}/products?id=1' -> DB error leaked in response body",
        },
        {
            "vulnerability": "Missing Security Headers",
            "severity": Severity.low,
            "description": "Response is missing Content-Security-Policy and X-Frame-Options headers.",
            "evidence": f"HEAD {target} -> no CSP / X-Frame-Options in response headers",
        },
        {
            "vulnerability": "Outdated jQuery Library (CVE-2020-11022)",
            "severity": Severity.medium,
            "description": "A bundled jQuery version with a known prototype-pollution/XSS CVE was detected.",
            "evidence": f"{target}/assets/js/jquery-1.12.4.min.js matched template jquery-cve-2020-11022",
        },
        {
            "vulnerability": "Exposed .git Directory",
            "severity": Severity.high,
            "description": "The .git directory is publicly accessible, potentially leaking source code and history.",
            "evidence": f"GET {target}/.git/HEAD -> HTTP 200",
        },
    ]


def demo_zap_findings(target: str) -> list[dict]:
    return [
        {
            "vulnerability": "SQL Injection",
            "severity": Severity.high,
            "description": "Active scan confirmed boolean-based blind SQL injection on a query parameter.",
            "evidence": f"{target}/products?id=1 AND 1=1 vs 1=2 -> divergent response length",
        },
        {
            "vulnerability": "Cross-Site Scripting (Reflected)",
            "severity": Severity.medium,
            "description": "User-supplied input is reflected in the HTML response without encoding.",
            "evidence": f"{target}/search?q=<script>alert(1)</script> reflected unescaped",
        },
        {
            "vulnerability": "Missing Security Headers",
            "severity": Severity.low,
            "description": "Content-Security-Policy header absent across scanned URLs.",
            "evidence": f"Passive scan of {target}: 12/12 responses missing CSP",
        },
        {
            "vulnerability": "Cookie Without HttpOnly Flag",
            "severity": Severity.low,
            "description": "Session cookie can be accessed via client-side script, enabling session theft via XSS.",
            "evidence": f"Set-Cookie: session=... (no HttpOnly) on {target}",
        },
    ]


def demo_nikto_findings(target: str) -> list[dict]:
    return [
        {
            "vulnerability": "Missing Security Headers",
            "severity": Severity.low,
            "description": "The X-Content-Type-Options header is not set.",
            "evidence": f"{target}: header 'X-Content-Type-Options' not present",
        },
        {
            "vulnerability": "Outdated Server Software",
            "severity": Severity.medium,
            "description": "Server banner discloses a web server version with known public vulnerabilities.",
            "evidence": f"{target} Server: nginx/1.18.0 (outdated, EOL)",
        },
        {
            "vulnerability": "Directory Listing Enabled",
            "severity": Severity.medium,
            "description": "Directory indexing is enabled on an uploads/static path, exposing file listings.",
            "evidence": f"GET {target}/uploads/ -> Index of /uploads",
        },
    ]


def whatweb_fallback(target: str) -> list[dict]:
    return [
        {
            "vulnerability": "Web Technology Stack Fingerprint",
            "severity": Severity.info,
            "description": f"Identified web technologies: Apache/2.4.41, OpenSSL/1.1.1f, PHP/7.4.3, Ubuntu Linux on {target}.",
            "evidence": f"{target} [200 OK] Apache[2.4.41], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[45.33.32.156], OpenSSL[1.1.1f]",
            "reference": "https://github.com/urbanadventurer/WhatWeb",
        },
        {
            "vulnerability": "PHP Version Disclosure",
            "severity": Severity.info,
            "description": "Server exposes exact PHP runtime version in X-Powered-By header.",
            "evidence": f"{target} headers: X-Powered-By: PHP/7.4.3",
            "reference": "https://cwe.mitre.org/data/definitions/200.html",
        },
    ]


def build_simulated_findings(tool: ScannerName, target: str) -> list[ScannerFinding]:
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]

    # 1. Use deterministic test-suite data for local/demo environments
    is_demo = clean_target.endswith(".local") or "demo" in clean_target.lower()
    if is_demo:
        demo_builders = {
            ScannerName.nuclei: demo_nuclei_findings,
            ScannerName.zap: demo_zap_findings,
            ScannerName.nikto: demo_nikto_findings,
        }
        if tool in demo_builders:
            raw_list = demo_builders[tool](clean_target)
            return [
                ScannerFinding(
                    tool=tool,
                    target=clean_target,
                    vulnerability=item["vulnerability"],
                    severity=item["severity"],
                    description=item["description"],
                    evidence=item["evidence"],
                    reference=enrich_reference(item["vulnerability"], None),
                )
                for item in raw_list
            ]

    # 2. Comprehensive dataset from standardized_scan_results.json (50+ items for scanme.sh and perimeters)
    dataset = get_all_dataset()
    findings: list[ScannerFinding] = []

    for item in dataset:
        raw_tool = str(item.get("tool", "")).lower()
        mapped_tool = TOOL_MAP.get(raw_tool)
        if mapped_tool == tool:
            raw_target = str(item.get("target", ""))
            port_suffix = ""
            if ":" in raw_target and not raw_target.startswith(("http://", "https://")):
                port_suffix = ":" + raw_target.split(":")[-1]

            item_target = f"{clean_target}{port_suffix}" if port_suffix else clean_target
            sev_str = str(item.get("severity", "info")).lower()
            sev = SEVERITY_CONV.get(sev_str, Severity.info)
            vuln = item.get("vulnerability", "Security Finding")
            desc = item.get("description", "Vulnerability detected by security engine.")
            evidence = item.get("evidence", "")
            ref = item.get("reference")

            # Enrich generic titles with specific descriptors so multi-item tools (Nikto, Wapiti)
            # are not collapsed by deduplication and properly represent distinct vulnerabilities
            if tool == ScannerName.nikto and vuln == "Nikto Web Finding":
                clean_desc = desc.split("]: ", 1)[-1] if "]: " in desc else desc
                clean_desc = clean_desc.split("/: ", 1)[-1] if "/: " in clean_desc else clean_desc
                vuln = clean_desc[:70].strip()
                evidence = f"{evidence} | {clean_desc[:50]}"
            elif tool == ScannerName.wapiti and vuln == "TLS/SSL misconfigurations":
                vuln = f"TLS/SSL: {desc[:55]}"
                evidence = f"{evidence} | {desc[:50]}"

            findings.append(
                ScannerFinding(
                    tool=tool,
                    target=item_target,
                    vulnerability=vuln,
                    severity=sev,
                    description=desc,
                    evidence=evidence,
                    reference=enrich_reference(vuln, ref if ref and ref != "N/A" else None),
                )
            )

    # 3. If tool is WhatWeb and dataset had none, use whatweb_fallback
    if tool == ScannerName.whatweb and not findings:
        for item in whatweb_fallback(clean_target):
            findings.append(
                ScannerFinding(
                    tool=ScannerName.whatweb,
                    target=clean_target,
                    vulnerability=item["vulnerability"],
                    severity=item["severity"],
                    description=item["description"],
                    evidence=item["evidence"],
                    reference=enrich_reference(item["vulnerability"], item["reference"]),
                )
            )

    # 4. Fallback defaults if dataset is not found
    if not findings:
        if tool == ScannerName.nmap:
            findings.append(
                ScannerFinding(
                    tool=ScannerName.nmap,
                    target=f"{clean_target}:80",
                    vulnerability="http-slowloris-check",
                    severity=Severity.medium,
                    description="VULNERABLE: Slowloris DOS attack potential detected.",
                    evidence=f"{clean_target}:80 open http Apache 2.4.41",
                    reference=enrich_reference("http-slowloris-check", "https://nmap.org/nsedoc/scripts/http-slowloris-check.html"),
                )
            )
        elif tool == ScannerName.sslyze:
            findings.append(
                ScannerFinding(
                    tool=ScannerName.sslyze,
                    target=f"https://{clean_target}",
                    vulnerability="TLS 1.0 Supported",
                    severity=Severity.medium,
                    description="The server supports the deprecated TLS 1.0 protocol.",
                    evidence=f"TLS 1.0 is accepted by {clean_target}:443",
                    reference=enrich_reference("TLS 1.0 Supported", "https://datatracker.ietf.org/doc/html/rfc8996"),
                )
            )
        elif tool == ScannerName.wapiti:
            findings.append(
                ScannerFinding(
                    tool=ScannerName.wapiti,
                    target=clean_target,
                    vulnerability="Clickjacking Protection Missing",
                    severity=Severity.low,
                    description="X-Frame-Options or CSP frame-ancestors is not set on HTTP endpoints.",
                    evidence=f"GET http://{clean_target}/ - header missing",
                    reference=enrich_reference("Clickjacking Protection", "https://wapiti-scanner.github.io/"),
                )
            )
        elif tool == ScannerName.nuclei:
            for item in demo_nuclei_findings(clean_target):
                findings.append(
                    ScannerFinding(
                        tool=ScannerName.nuclei,
                        target=clean_target,
                        vulnerability=item["vulnerability"],
                        severity=item["severity"],
                        description=item["description"],
                        evidence=item["evidence"],
                        reference=enrich_reference(item["vulnerability"], None),
                    )
                )

    return findings
