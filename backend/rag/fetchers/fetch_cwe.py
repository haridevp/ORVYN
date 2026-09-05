"""
Fetches the CWE catalog (XML) from cwe.mitre.org and parses weaknesses
into a flat list of {id, title, description, url}.

Usage:
    python fetch_cwe.py
Output:
    ../data/raw/cwe_data.json
"""

import requests
import zipfile
import io
import json
import os
import xml.etree.ElementTree as ET

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "cwe_data.json")


def fetch_cwe():
    print("[*] Downloading CWE catalog...")
    resp = requests.get(CWE_ZIP_URL, timeout=60)
    resp.raise_for_status()

    z = zipfile.ZipFile(io.BytesIO(resp.content))
    xml_filenames = [n for n in z.namelist() if n.endswith(".xml")]
    if not xml_filenames:
        raise RuntimeError("No XML file found in CWE zip archive")

    xml_filename = xml_filenames[0]
    print(f"[*] Parsing {xml_filename}...")

    tree = ET.parse(z.open(xml_filename))
    root = tree.getroot()

    # Namespace can shift between MITRE releases — detect it dynamically
    ns_uri = root.tag.split("}")[0].strip("{") if "}" in root.tag else ""
    ns = {"cwe": ns_uri} if ns_uri else {}

    weaknesses = []
    findall_path = ".//cwe:Weakness" if ns else ".//Weakness"

    for weakness in root.findall(findall_path, ns):
        cwe_num = weakness.get("ID")
        name = weakness.get("Name")

        desc_path = "cwe:Description" if ns else "Description"
        desc_el = weakness.find(desc_path, ns)
        desc = (desc_el.text or "").strip() if desc_el is not None else ""

        # Some entries have extended description too — append if present
        ext_desc_path = "cwe:Extended_Description" if ns else "Extended_Description"
        ext_desc_el = weakness.find(ext_desc_path, ns)
        if ext_desc_el is not None and ext_desc_el.text:
            desc += " " + ext_desc_el.text.strip()

        if not desc:
            continue

        weaknesses.append({
            "source_id": f"CWE-{cwe_num}",
            "title": name,
            "text": desc,
            "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
        })

    return weaknesses


def main():
    weaknesses = fetch_cwe()

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(weaknesses, f, indent=2)

    print(f"[✓] Saved {len(weaknesses)} CWE entries to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()