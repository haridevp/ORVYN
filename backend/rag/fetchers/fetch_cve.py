"""
Fetches CVE data from the NVD API 2.0, scoped to relevant vulnerability
keywords (SQLi, XSS, SSRF, XXE, RCE, etc.) rather than the full database.

Usage:
    python fetch_cve.py
Output:
    ../data/raw/cve_data.json
"""

# TODO: implement fetch_cves_by_keyword() and normalize_cve()
