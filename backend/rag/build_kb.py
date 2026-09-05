"""
Orchestrator: reads data/raw/*.json produced by the fetchers, applies the
appropriate chunking strategy per source, and loads everything into
ChromaDB via loaders/load_to_chroma.py.

Run order:
    python fetchers/fetch_cve.py
    python fetchers/fetch_mitre.py
    python fetchers/fetch_cwe.py
    python fetchers/fetch_owasp.py
    python build_kb.py
"""

import json
import os
from chunkers.chunker import process_source
from loaders.load_to_chroma import load_chunks

RAW_DIR = os.path.join(os.path.dirname(__file__), "data", "raw")


def load_raw(filename):
    path = os.path.join(RAW_DIR, filename)
    if not os.path.exists(path):
        print(f"[!] Missing {path} — run the corresponding fetcher first.")
        return []
    with open(path) as f:
        return json.load(f)


def main():
    all_chunks = []

    print("[*] Processing CVE data...")
    cve_raw = load_raw("cve_data.json")
    cve_chunks = process_source(cve_raw, "CVE", max_chars=1000, overlap=100)
    print(f"    {len(cve_raw)} entries -> {len(cve_chunks)} chunks")
    all_chunks += cve_chunks

    print("[*] Processing MITRE ATT&CK data...")
    mitre_raw = load_raw("mitre_attack.json")
    mitre_chunks = process_source(mitre_raw, "MITRE_ATTACK", max_chars=1000, overlap=100)
    print(f"    {len(mitre_raw)} entries -> {len(mitre_chunks)} chunks")
    all_chunks += mitre_chunks

    print("[*] Processing CWE data...")
    cwe_raw = load_raw("cwe_data.json")
    cwe_chunks = process_source(cwe_raw, "CWE", max_chars=1000, overlap=100)
    print(f"    {len(cwe_raw)} entries -> {len(cwe_chunks)} chunks")
    all_chunks += cwe_chunks

    print("[*] Processing OWASP data...")
    owasp_raw = load_raw("owasp_data.json")
    owasp_chunks = process_source(owasp_raw, "OWASP", use_markdown_chunking=True,
                                    max_chars=1200, overlap=100)
    print(f"    {len(owasp_raw)} entries -> {len(owasp_chunks)} chunks")
    all_chunks += owasp_chunks

    print(f"\n[*] Total chunks to load: {len(all_chunks)}")

    if not all_chunks:
        print("[!] No chunks produced — check that fetchers have been run.")
        return

    load_chunks(all_chunks)


if __name__ == "__main__":
    main()