"""
Fetches CVE data from the NVD API 2.0, scoped to relevant vulnerability
keywords rather than the full database.

Usage:
    python fetch_cve.py
Output:
    ../data/raw/cve_data.json
"""

import requests
import time
import json
import os

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Keywords scoped to what your scanners (Nuclei/ZAP/Nikto) actually detect
KEYWORDS = [
    "SQL injection",
    "cross-site scripting",
    "server-side request forgery",
    "XML external entity",
    "remote code execution",
    "path traversal",
    "insecure deserialization",
    "broken authentication",
    "security misconfiguration",
    "command injection",
]

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "cve_data.json")


def fetch_cves_by_keyword(keyword, results_per_page=50, max_pages=2, api_key=None):
    """Fetch CVEs matching a keyword, paginated."""
    all_cves = []
    start_index = 0
    headers = {"apiKey": api_key} if api_key else {}

    for page in range(max_pages):
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        try:
            resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"  [!] Request failed for '{keyword}' page {page}: {e}")
            break

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        all_cves.extend(vulns)
        start_index += results_per_page

        # Respect NVD public rate limit (~5 requests / 30s without API key)
        sleep_time = 1 if api_key else 6
        time.sleep(sleep_time)

    return all_cves


def normalize_cve(entry):
    """Convert raw NVD entry into flat schema."""
    cve = entry["cve"]
    cve_id = cve["id"]

    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        ""
    )

    severity = None
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics:
        severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity")
    elif "cvssMetricV30" in metrics:
        severity = metrics["cvssMetricV30"][0]["cvssData"].get("baseSeverity")
    elif "cvssMetricV2" in metrics:
        severity = metrics["cvssMetricV2"][0].get("baseSeverity")

    return {
        "source_id": cve_id,
        "title": cve_id,
        "text": desc,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "severity": severity,
    }


def main():
    api_key = os.environ.get("NVD_API_KEY")  # optional, set via env var if you have one
    if not api_key:
        print("[i] No NVD_API_KEY found in env — using public rate limit (slower).")

    all_normalized = []
    seen_ids = set()

    for kw in KEYWORDS:
        print(f"[*] Fetching CVEs for keyword: '{kw}'")
        raw = fetch_cves_by_keyword(kw, max_pages=2, api_key=api_key)
        print(f"    -> {len(raw)} raw entries")

        for entry in raw:
            normalized = normalize_cve(entry)
            if normalized["source_id"] not in seen_ids and normalized["text"]:
                seen_ids.add(normalized["source_id"])
                all_normalized.append(normalized)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(all_normalized, f, indent=2)

    print(f"\n[✓] Saved {len(all_normalized)} unique CVEs to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()