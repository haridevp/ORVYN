# RAG Knowledge Base

Ingests CVE, MITRE ATT&CK, CWE, and OWASP data into a persistent ChromaDB
collection (`security_knowledge`) for use by the RAG retrieval pipeline
(Module 3).

## Local models

- Ollama running locally (`ollama --version` → 0.33.3)
- Model used: `qwen2.5:3b`

## Setup

```bash
pip install -r requirements.txt
```

## Build the knowledge base

```bash
cd backend/rag
python fetchers/fetch_cve.py
python fetchers/fetch_mitre.py
python fetchers/fetch_cwe.py
python fetchers/fetch_owasp.py
python build_kb.py
```

## Verify

```bash
python tests/test_retrieval.py
```

## Schema

Each chunk stored in ChromaDB has:

- `id`: unique chunk identifier
- `document`: chunk text
- `metadata`: `{source, source_id, title, url, chunk_index}`

## Status

Knowledge base built — 5,582 chunks total

- CVE: ~919 source entries
- MITRE ATT&CK: ~697 source entries
- CWE: ~969 source entries
- OWASP: ~100 source entries (cheat sheets, header-chunked)

Run `python build_kb.py` locally to regenerate (not committed — see .gitignore).
