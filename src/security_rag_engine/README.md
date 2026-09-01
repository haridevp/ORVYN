# Module 3: Cybersecurity RAG & AI Triage Engine

This module serves as the RAG (Retrieval-Augmented Generation) layer and local LLM connector for an automated cybersecurity vulnerability assessment platform.

## Features

1. **Local LLM Integration**: Interfaces with a local LLM instance (e.g., Qwen 2.5) via an OpenAI-compatible API (LM Studio).
2. **Vector Database**: Uses ChromaDB and `all-MiniLM-L6-v2` embeddings for storing and retrieving cybersecurity knowledge (OWASP, CWE, CVE mitigations).
3. **Scanner Finding Ingestion**: Accepts normalized findings from tools like Nuclei, ZAP, Nikto, Trivy, and Nmap-Vulners.
4. **Hybrid Retrieval**: Enhances finding context with semantically retrieved knowledge.
5. **AI Triage**: Generates deterministic, structured JSON triage assessments including validated severity, confidence score, threat explanation, and remediation guidance.
6. **Historical Engine**: Computes scan deltas (persistent, resolved, new findings) for downstream analysis.

## Setup Instructions

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure LM Studio**
   - Start your local LM Studio instance.
   - Load a compatible model (e.g., Qwen 2.5 or Qwen 3.5).
   - Start the local server (default: `http://localhost:1234/v1`).
   - If using a different URL or model, update the environment variables or `config.py`.

3. **Run the API Server**
   ```bash
   uvicorn main:app --reload
   ```

4. **Seed the Knowledge Base**
   - Trigger the `/api/v1/kb/seed` endpoint to populate ChromaDB.
   ```bash
   curl -X POST http://127.0.0.1:8000/api/v1/kb/seed
   ```

## Running Tests

A standalone test suite is provided via pytest:

```bash
pytest test_rag.py -v
```

This tests the ChromaDB ingestion, retrieval, prompt generation, JSON parsing, and the historical delta engine.

## API Endpoints

- `GET /health`: Checks API and LM Studio status.
- `POST /api/v1/kb/seed`: Populates the vector database.
- `POST /api/v1/triage/single`: Triages a single scanner finding.
- `POST /api/v1/triage/batch`: Triages a list of scanner findings asynchronously.
- `POST /api/v1/history/diff`: Compares current findings against previous findings to determine state (new, resolved, persistent).
