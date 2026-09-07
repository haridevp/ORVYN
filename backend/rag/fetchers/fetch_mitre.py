"""
Fetches MITRE ATT&CK Enterprise techniques from the public STIX bundle
on GitHub (mitre/cti repo). No API key required.

Usage:
    python fetch_mitre.py
Output:
    ../data/raw/mitre_attack.json
"""

import requests
import json
import os

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "mitre_attack.json")


def fetch_attack_techniques():
    print("[*] Downloading MITRE ATT&CK Enterprise bundle...")
    resp = requests.get(ATTACK_URL, timeout=60)
    resp.raise_for_status()
    bundle = resp.json()

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        technique_id = None
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url", "")
                break

        if not technique_id:
            continue

        techniques.append({
            "source_id": technique_id,
            "title": obj.get("name", ""),
            "text": obj.get("description", ""),
            "url": url,
        })

    return techniques


def main():
    techniques = fetch_attack_techniques()

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(techniques, f, indent=2)

    print(f"[✓] Saved {len(techniques)} ATT&CK techniques to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()