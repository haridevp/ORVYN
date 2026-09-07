"""Deterministic demo findings used when a scanner binary isn't installed.

The overlaps here are intentional: "Missing Security Headers" is reported by
all three tools (high-confidence correlation) and "SQL Injection" is reported
by both Nuclei and ZAP with *different* severities (medium vs. high), so the
correlation engine has a real conflicting-severity case to resolve, not just
happy-path data.
"""

from schemas import ScannerFinding, ScannerName, Severity


def nuclei_findings(target: str) -> list[dict]:
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


def zap_findings(target: str) -> list[dict]:
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


def nikto_findings(target: str) -> list[dict]:
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


SIMULATED_BUILDERS = {
    ScannerName.nuclei: nuclei_findings,
    ScannerName.zap: zap_findings,
    ScannerName.nikto: nikto_findings,
}


def build_simulated_findings(tool: ScannerName, target: str) -> list[ScannerFinding]:
    from references import enrich_reference

    raw = SIMULATED_BUILDERS[tool](target)
    findings = []
    for item in raw:
        findings.append(
            ScannerFinding(
                tool=tool,
                target=target,
                vulnerability=item["vulnerability"],
                severity=item["severity"],
                description=item["description"],
                evidence=item["evidence"],
                reference=enrich_reference(item["vulnerability"], None),
            )
        )
    return findings
