"""Static security reference taxonomy used to enrich findings with citations.

Sourced from OWASP Top 10:2025 (owasp.org/Top10/2025) and the CWE Top 25:2024
(cwe.mitre.org/top25/archive/2024). Kept as plain data so the RAG knowledge
base (Module 3) can reuse the same taxonomy without importing FastAPI.
"""

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
}

# Keyword -> (CWE id, OWASP category) used to enrich findings that scanners
# report without a CWE/OWASP tag of their own (Nikto/plain-text scanners).
VULNERABILITY_KEYWORD_MAP: dict[str, tuple[str, str]] = {
    "sql injection": ("CWE-89", "A05:2025"),
    "cross-site scripting": ("CWE-79", "A05:2025"),
    "xss": ("CWE-79", "A05:2025"),
    "csrf": ("CWE-352", "A06:2025"),
    "path traversal": ("CWE-22", "A01:2025"),
    "directory traversal": ("CWE-22", "A01:2025"),
    "command injection": ("CWE-78", "A05:2025"),
    "ssrf": ("CWE-918", "A05:2025"),
    "server-side request forgery": ("CWE-918", "A05:2025"),
    "missing authorization": ("CWE-862", "A01:2025"),
    "broken access control": ("CWE-862", "A01:2025"),
    "file upload": ("CWE-434", "A08:2025"),
    "deserialization": ("CWE-502", "A08:2025"),
    "sensitive information": ("CWE-200", "A02:2025"),
    "information disclosure": ("CWE-200", "A02:2025"),
    "hard-coded credentials": ("CWE-798", "A07:2025"),
    "default credentials": ("CWE-798", "A07:2025"),
    "authentication": ("CWE-287", "A07:2025"),
    "tls": ("CWE-326", "A04:2025"),
    "ssl": ("CWE-326", "A04:2025"),
    "certificate": ("CWE-295", "A04:2025"),
    "security misconfiguration": ("CWE-16", "A02:2025"),
    "server header": ("CWE-200", "A02:2025"),
    "outdated software": ("CWE-1104", "A03:2025"),
}


def enrich_reference(vulnerability_title: str, existing_reference: str | None) -> str | None:
    """Best-effort CWE/OWASP citation for a finding based on its title."""
    if existing_reference:
        return existing_reference
    title_lower = vulnerability_title.lower()
    for keyword, (cwe_id, owasp_id) in VULNERABILITY_KEYWORD_MAP.items():
        if keyword in title_lower:
            owasp_name = OWASP_TOP_10_2025.get(owasp_id, "")
            cwe_name = CWE_TOP_25_2024.get(cwe_id, "")
            return f"{cwe_id} ({cwe_name}) / OWASP {owasp_id} - {owasp_name}"
    return None
