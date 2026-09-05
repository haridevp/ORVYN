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

# TODO: implement process_source() and main()
