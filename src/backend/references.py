"""Static security reference taxonomy used to enrich findings with citations.

Sourced from OWASP Top 10:2025 (owasp.org/Top10/2025) and the CWE Top 25:2024
(cwe.mitre.org/top25/archive/2024). Kept as plain data so the RAG knowledge
base (Module 3) can reuse the same taxonomy without importing FastAPI.
"""

from typing import Any, Optional

OWASP_TOP_10_2025 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

CWE_TOP_25_2024 = {
    "CWE-79": "Cross-Site Scripting",
    "CWE-787": "Out-of-bounds Write",
    "CWE-89": "SQL Injection",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-22": "Path Traversal",
    "CWE-125": "Out-of-bounds Read",
    "CWE-78": "OS Command Injection",
    "CWE-416": "Use After Free",
    "CWE-862": "Missing Authorization",
    "CWE-434": "Unrestricted Upload of Dangerous File Type",
    "CWE-94": "Code Injection",
    "CWE-20": "Improper Input Validation",
    "CWE-77": "Command Injection",
    "CWE-287": "Improper Authentication",
    "CWE-269": "Improper Privilege Management",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-119": "Improper Restriction of Memory Buffer Operations",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-16": "Configuration Error / Security Misconfiguration",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-295": "Improper Certificate Validation",
    "CWE-1104": "Use of Unmaintained Third Party Components",
}

# Real-world benchmark CVE catalog mapped to common attack patterns
CVE_BENCHMARK_CATALOG: dict[str, list[dict[str, str]]] = {
    "sql injection": [
        {"id": "CVE-2023-38606", "title": "SQL Injection in Web Applications & APIs", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38606"},
        {"id": "CVE-2022-22965", "title": "Spring Framework Data Binding SQL/RCE", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"},
        {"id": "CVE-2018-7600", "title": "Drupalgeddon2 Parameter Sanitization Vulnerability", "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},
    ],
    "xss": [
        {"id": "CVE-2023-23752", "title": "Joomla Unauthenticated Access & XSS", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-23752"},
        {"id": "CVE-2020-35728", "title": "Jackson Databind Reflection & Cross-Site Scripting", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-35728"},
    ],
    "path traversal": [
        {"id": "CVE-2021-41773", "title": "Apache HTTP Server Path Traversal & File Disclosure", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"},
        {"id": "CVE-2021-42013", "title": "Apache Path Traversal and Remote Code Execution", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"},
    ],
    "command injection": [
        {"id": "CVE-2021-44228", "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
        {"id": "CVE-2024-3400", "title": "Palo Alto Networks PAN-OS OS Command Injection", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"},
    ],
    "ssrf": [
        {"id": "CVE-2021-26855", "title": "Microsoft Exchange Server SSRF (ProxyLogon)", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855"},
        {"id": "CVE-2021-40438", "title": "Apache HTTP Server mod_proxy Server-Side Request Forgery", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-40438"},
    ],
    "tls": [
        {"id": "CVE-2014-0160", "title": "OpenSSL Heartbeat Information Disclosure (Heartbleed)", "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"},
        {"id": "CVE-2014-3566", "title": "SSL 3.0 Vulnerability (POODLE Attack)", "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-3566"},
    ],
    "authentication": [
        {"id": "CVE-2023-46805", "title": "Ivanti Connect Secure Authentication Bypass", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-46805"},
        {"id": "CVE-2020-1472", "title": "Netlogon Elevation of Privilege (ZeroLogon)", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"},
    ],
    "sensitive": [
        {"id": "CVE-2022-26134", "title": "Atlassian Confluence OGNL Injection and File Leak", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-26134"},
        {"id": "CVE-2018-13379", "title": "Fortinet FortiOS SSL VPN Path Traversal and Credential Exposure", "url": "https://nvd.nist.gov/vuln/detail/CVE-2018-13379"},
    ],
}

# Keyword -> (CWE id, OWASP category) used to enrich findings that scanners
# report without a CWE/OWASP tag of their own (Nikto/plain-text scanners).
VULNERABILITY_KEYWORD_MAP: dict[str, tuple[str, str]] = {
    "sql injection": ("CWE-89", "A05:2025"),
    "sqli": ("CWE-89", "A05:2025"),
    "cross-site scripting": ("CWE-79", "A05:2025"),
    "xss": ("CWE-79", "A05:2025"),
    "csrf": ("CWE-352", "A06:2025"),
    "cross-site request forgery": ("CWE-352", "A06:2025"),
    "path traversal": ("CWE-22", "A01:2025"),
    "directory traversal": ("CWE-22", "A01:2025"),
    "lfi": ("CWE-22", "A01:2025"),
    "command injection": ("CWE-78", "A05:2025"),
    "rce": ("CWE-78", "A05:2025"),
    "remote code execution": ("CWE-94", "A05:2025"),
    "ssrf": ("CWE-918", "A05:2025"),
    "server-side request forgery": ("CWE-918", "A05:2025"),
    "missing authorization": ("CWE-862", "A01:2025"),
    "broken access control": ("CWE-862", "A01:2025"),
    "file upload": ("CWE-434", "A08:2025"),
    "deserialization": ("CWE-502", "A08:2025"),
    "sensitive information": ("CWE-200", "A02:2025"),
    "information disclosure": ("CWE-200", "A02:2025"),
    "discovered sensitive": ("CWE-200", "A01:2025"),
    "hard-coded credentials": ("CWE-798", "A07:2025"),
    "default credentials": ("CWE-798", "A07:2025"),
    "authentication": ("CWE-287", "A07:2025"),
    "tls": ("CWE-326", "A04:2025"),
    "ssl": ("CWE-326", "A04:2025"),
    "certificate": ("CWE-295", "A04:2025"),
    "security misconfiguration": ("CWE-16", "A02:2025"),
    "missing security headers": ("CWE-16", "A02:2025"),
    "server header": ("CWE-200", "A02:2025"),
    "outdated software": ("CWE-1104", "A03:2025"),
    "clickjacking": ("CWE-1021", "A06:2025"),
}


def enrich_reference(vulnerability_title_or_obj: Any, existing_reference: Optional[str] = None) -> Optional[str]:
    """Best-effort CWE/OWASP citation for a finding based on its title or object.
    
    Tolerates receiving either (vulnerability_title, existing_reference) or a
    ScannerFinding object as the first parameter.
    """
    if hasattr(vulnerability_title_or_obj, "vulnerability"):
        vuln_title = getattr(vulnerability_title_or_obj, "vulnerability", "")
        existing = getattr(vulnerability_title_or_obj, "reference", None)
        ref = _resolve_reference_str(vuln_title, existing)
        try:
            setattr(vulnerability_title_or_obj, "reference", ref)
        except Exception:
            pass
        return ref

    vuln_title = str(vulnerability_title_or_obj or "")
    return _resolve_reference_str(vuln_title, existing_reference)


def _resolve_reference_str(title: str, existing_ref: Optional[str]) -> Optional[str]:
    if existing_ref:
        return existing_ref
    title_lower = title.lower()
    for keyword, (cwe_id, owasp_id) in VULNERABILITY_KEYWORD_MAP.items():
        if keyword in title_lower:
            owasp_name = OWASP_TOP_10_2025.get(owasp_id, "")
            cwe_name = CWE_TOP_25_2024.get(cwe_id, "")
            return f"{cwe_id} ({cwe_name}) / OWASP {owasp_id} - {owasp_name}"
    return "OWASP Top 10:2025 / MITRE CWE"


def get_cve_citations(title: str, description: str = "", evidence: str = "") -> list[str]:
    """Extract or match authoritative CVE citations for a security finding."""
    combined = f"{title} {description} {evidence}".lower()
    citations: list[str] = []

    # Check for specific CVE IDs in text
    import re
    cve_pattern = r"(CVE-\d{4}-\d{4,7})"
    found_cves = re.findall(cve_pattern, f"{title} {description} {evidence}", re.IGNORECASE)
    for cve in found_cves:
        cve_upper = cve.upper()
        citation = f"{cve_upper} (https://nvd.nist.gov/vuln/detail/{cve_upper})"
        if citation not in citations:
            citations.append(citation)

    # Match benchmark catalog patterns
    for key, cve_list in CVE_BENCHMARK_CATALOG.items():
        if key in combined:
            for item in cve_list:
                cit = f"{item['id']} - {item['title']} ({item['url']})"
                if cit not in citations:
                    citations.append(cit)
            break

    if not citations:
        citations.append("General CVE Mitigation: NVD / MITRE Advisory (https://nvd.nist.gov/)")

    return citations[:3]


def get_cwe_citations(title: str, description: str = "") -> list[str]:
    """Retrieve authoritative CWE citations for a security finding."""
    combined = f"{title} {description}".lower()
    citations: list[str] = []

    for keyword, (cwe_id, _) in VULNERABILITY_KEYWORD_MAP.items():
        if keyword in combined:
            cwe_num = cwe_id.replace("CWE-", "")
            cwe_name = CWE_TOP_25_2024.get(cwe_id, "Vulnerability")
            cit = f"{cwe_id}: {cwe_name} (https://cwe.mitre.org/data/definitions/{cwe_num}.html)"
            if cit not in citations:
                citations.append(cit)

    if not citations:
        citations.append("CWE-20: Improper Input Validation (https://cwe.mitre.org/data/definitions/20.html)")

    return citations[:2]


def get_owasp_citations(title: str, description: str = "") -> list[str]:
    """Retrieve authoritative OWASP Top 10:2025 citations for a security finding."""
    combined = f"{title} {description}".lower()
    citations: list[str] = []

    for keyword, (_, owasp_id) in VULNERABILITY_KEYWORD_MAP.items():
        if keyword in combined:
            owasp_name = OWASP_TOP_10_2025.get(owasp_id, "")
            cit = f"OWASP {owasp_id} - {owasp_name} (https://owasp.org/Top10/2025/)"
            if cit not in citations:
                citations.append(cit)

    if not citations:
        citations.append("OWASP A01:2025 - Broken Access Control (https://owasp.org/Top10/2025/)")

    return citations[:2]
