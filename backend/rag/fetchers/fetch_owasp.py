"""
Fetches OWASP Cheat Sheet Series markdown files via the GitHub API.

Usage:
    python fetch_owasp.py
Output:
    ../data/raw/owasp_data.json
"""

import requests
import json
import os
import time

CHEATSHEET_INDEX = "https://api.github.com/repos/OWASP/CheatSheetSeries/contents/cheatsheets"
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "owasp_data.json")


def fetch_owasp_cheatsheets(limit=100):
    print("[*] Fetching OWASP Cheat Sheet index...")
    resp = requests.get(CHEATSHEET_INDEX, timeout=30)
    resp.raise_for_status()
    files = resp.json()

    if isinstance(files, dict) and files.get("message"):
        # GitHub API rate limit or error response
        raise RuntimeError(f"GitHub API error: {files.get('message')}")

    docs = []
    md_files = [f for f in files if f["name"].endswith(".md")][:limit]

    for i, f in enumerate(md_files):
        try:
            raw = requests.get(f["download_url"], timeout=30).text
        except requests.exceptions.RequestException as e:
            print(f"  [!] Failed to fetch {f['name']}: {e}")
            continue

        title = f["name"].replace("_Cheat_Sheet.md", "").replace(".md", "").replace("_", " ")
        docs.append({
            "source_id": f["name"].replace(".md", ""),
            "title": title,
            "text": raw,
            "url": f["html_url"],
        })

        if (i + 1) % 10 == 0:
            print(f"    -> fetched {i + 1}/{len(md_files)}")

        time.sleep(0.3)  # be polite to unauthenticated GitHub API (60 req/hr limit)

    return docs


def main():
    docs = fetch_owasp_cheatsheets()

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(docs, f, indent=2)

    print(f"[✓] Saved {len(docs)} OWASP cheat sheets to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()