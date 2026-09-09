# Developer & LLM Integration Guide

Welcome to the **ORVYN (Offensive Risk and Vulnerability Intelligence Network)** developer documentation. This guide details the platform architecture, how the autonomous LLM template orchestrator works, how the RAG (Retrieval-Augmented Generation) engine works, and how to connect, configure, and switch local LLMs (Ollama & LM Studio).

---

## 🏛️ 1. Architecture Overview

The platform consists of four primary modules:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           React Frontend (Vite)                         │
│   (Real-time Dashboard, Topology Graph, Live Findings, PDF Reports)     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTP / SSE
┌────────────────────────────────────▼────────────────────────────────────┐
│                           FastAPI API Gateway                           │
│   • Scans Job Manager              • Result Normalizer & Correlator     │
│   • Scope & Perimeter Filter       • Celery / Redis Task Dispatcher     │
└──────────────────┬───────────────────────────────────┬──────────────────┘
                   │                                   │
        ┌──────────▼──────────┐             ┌──────────▼──────────┐
        │   Security Scanners │             │  Cybersecurity RAG  │
        │  • Nuclei   • ZAP   │             │  & AI Triage Engine │
        │  • Nikto    • Nmap  │             │  (ChromaDB + LLM)   │
        │  • Wapiti   • SSLyze│             └──────────┬──────────┘
        └─────────────────────┘                        │
                                            ┌──────────▼──────────┐
                                            │ Local LLM Provider  │
                                            │ • Ollama (qwen2.5)  │
                                            │ • LM Studio (qwen3) │
                                            └─────────────────────┘
```

---

## 🤖 2. Local LLM Setup & Connection

The platform interfaces with local LLMs using an OpenAI-compatible HTTP API.

### **Default & Recommended Engine: Ollama (`qwen2.5:7b`)**

For automated vulnerability assessments, **`qwen2.5:7b` via Ollama is the default choice**. It produces direct, high-confidence structured JSON within **1.5 – 3 seconds** without burning tokens on long chain-of-thought delays.

#### **A. Installing & Running Ollama**
1. Install Ollama:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```
2. Pull the recommended security triage model:
   ```bash
   ollama pull qwen2.5:7b
   ```
3. Verify Ollama is listening (default: port `11434`):
   ```bash
   curl http://localhost:11434/api/tags
   ```

#### **B. Testing Ollama's OpenAI API**
Ollama natively provides an OpenAI-compatible endpoint at `http://localhost:11434/v1`:
```bash
curl http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "qwen2.5:7b",
    "messages": [{"role": "user", "content": "Respond only with JSON: {\"status\": \"ok\"}"}]
  }'
```

---

### **Alternative Engine: LM Studio (`qwen3.5:9b`)**

If you want deep, multi-step forensic reasoning for manual exploit analysis:
1. Open **LM Studio**.
2. Download `qwen3.5-9b` (or equivalent).
3. Navigate to the **Local Server** tab (port `1234`).
4. Click **Start Server**.
5. Set the model identifier to `qwen3.5-9b`.

> [!WARNING]
> **Reasoning Model Notice**: `qwen3.5:9b` outputs chain-of-thought `<think>` tokens before generating JSON. On single queries, this can take **30–60+ seconds**. Use it for deep analysis of specific critical findings, not high-volume real-time triage.

---

## ⚙️ 3. Hardware & VRAM Memory Guidelines

For systems with **4 GB to 6 GB VRAM** (e.g. NVIDIA GeForce RTX 3050):
* A **7B quantized model (Q4)** requires **~4.7 GB**.
* A **9B quantized model (Q4)** requires **~6.0 GB**.

Because 7B/9B models exceed 4 GB VRAM, the runtime splits layers across the GPU and system RAM:
* **Never keep both Ollama and LM Studio models loaded simultaneously.** Doing so will exhaust RAM and trigger system freezes or Linux OOM (Out Of Memory) kills.
* **To unload a model from Ollama immediately and free VRAM**:
  ```bash
  curl http://localhost:11434/api/generate -d '{"model": "qwen2.5:7b", "keep_alive": 0}'
  ```

---

## 🔧 4. Configuration & Environment Variables

All RAG and LLM settings are managed via environment variables.

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `LM_STUDIO_URL` | `http://localhost:11434/v1` | Base URL of the OpenAI-compatible LLM server |
| `MODEL_NAME` | `qwen2.5:7b` | Model name to invoke for triage |
| `CHROMA_PERSIST_DIR` | `./chroma_security_db` | Persistent vector database directory |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | SentenceTransformer embedding model for retrieval |
| `TEMPERATURE` | `0.1` | Sampling temperature (low for deterministic JSON) |

To override settings temporarily:
```bash
export LM_STUDIO_URL="http://localhost:1234/v1"
export MODEL_NAME="qwen3.5-9b"
```

---

## 🧠 5. How the RAG Pipeline Works

When security scanners detect a vulnerability:

1. **Extraction**: The vulnerability name, description, and raw evidence payload are normalized.
2. **Retrieval**: ChromaDB runs a cosine-similarity search against stored cybersecurity corpora (OWASP Top 10, CWE definitions, CVE mitigation catalogs) using `all-MiniLM-L6-v2`.
3. **Prompt Assembly**: The retrieved context and scanner findings are injected into a strict system prompt.
4. **LLM Inference**: The LLM analyzes the evidence against authoritative CWE rules to:
   * Validate or adjust reported severity (e.g., confirming whether an SQLi alert is genuine or a false positive).
   * Calculate an **AI Confidence Score (0–100%)**.
   * Produce a **Threat Narrative** explaining real-world exploitability.
   * Provide **Remediation Guidance** tailored to developers.
   * Attach authoritative CWE/CVE references.
5. **Output**: Parsed into `CorrelatedFinding` schema and rendered live in the React dashboard.

---

## 🚀 6. Running the Platform Locally

### Native Local Development
```bash
# 1. Start the complete platform in local dev mode
./start.sh --local

# 2. Access the components:
# • Frontend: http://localhost:5173
# • Backend API & Docs: http://localhost:8000/docs
```

### Docker Compose
```bash
./start.sh --docker
```

---

## 🧪 7. Running Automated Tests

```bash
# Activate your virtual environment
source .venv/bin/activate

# 1. Run RAG Engine & Vector DB tests
pytest tests/security_rag_engine/test_rag.py -v

# 2. Run Historical Scan Memory tests
pytest tests/security_rag_engine/test_history.py -v

# 3. Run Multi-Scanner & Correlation tests
pytest tests/test_multi_scanner.py -v
```

---

## 🔍 8. Troubleshooting

* **`Port 1234 / 11434 not allowed for HTTP`**:
  If running inside a containerized sandbox without network access, enable host networking or ensure the process has access to localhost loopback.
* **`JSONDecodeError during triage`**:
  Usually caused by reasoning models outputting markdown fences or thinking commentary. Qwen 2.5:7b with `temperature=0.1` prevents this.
* **`Model loading timeout`**:
  On first invocation ("cold start"), Ollama loads model weights from disk to RAM/VRAM. Subsequent calls will execute in ~1.5–3 seconds.

---

## 🛡️ 9. Autonomous LLM Template Selection & 30-Template Library

### Dynamic Autonomous Backend Selection Flow
The user does not need to choose individual tools or templates manually. When launching a scan with `--template auto` (the default in both Web UI and CLI):

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Phase 1: Initial Reconnaissance                    │
│   Runs non-intrusive perimeter fingerprinting: WhatWeb, Nmap, SSLyze    │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Discovered tech, ports & banners
┌────────────────────────────────────▼────────────────────────────────────┐
│              Phase 2: Autonomous LLM Orchestrator (Backend)            │
│   Local LLM (Qwen 2.5:7b) evaluates initial findings in 1.5–2.0s        │
│   Selects optimal template from 30 templates with technical reasoning  │
│   (Falls back to deterministic heuristic matcher if LLM is offline)     │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Selected Template ID & Toolchain
┌────────────────────────────────────▼────────────────────────────────────┐
│                 Phase 3: Targeted Secondary Tool Execution              │
│   Dynamically enqueues & executes missing tools from chosen template    │
│   (e.g., Nikto, Nuclei CVE tags, SQLMap, Ffuf, Wapiti, OWASP ZAP)       │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Raw scanner outputs
┌────────────────────────────────────▼────────────────────────────────────┐
│                    Phase 4: Post-Scan AI RAG Triage                     │
│   Deduplicates, scores CVSS, and verifies findings one by one with RAG  │
└─────────────────────────────────────────────────────────────────────────┘
```

### The 30 Curated Assessment Templates (5 Categories)

1. **CMS & Web Frameworks (6 Templates)**:
   - `cms_wordpress_deep_audit`: WordPress core, themes, plugin vulnerabilities, and XML-RPC exploitation.
   - `cms_drupal_audit`: Drupal core RCE (Drupalgeddon), modules, and database misconfigurations.
   - `cms_joomla_audit`: Joomla component vulnerabilities, SQL injection, and administrative exposure.
   - `framework_django_audit`: Django debug leak, secret key exposure, and admin interface discovery.
   - `framework_laravel_audit`: Laravel debug mode, `.env` file leak, Ignition RCE, and route exposures.
   - `framework_spring_boot_audit`: Spring Boot Actuator endpoint exposure, Jolokia RCE, and heap dump leaks.

2. **API, Cloud & Microservices (6 Templates)**:
   - `api_microservice_audit`: REST & GraphQL API audit, Swagger/OpenAPI leakage, and token exposure.
   - `cloud_kubernetes_metadata_audit`: Kubernetes API server exposure, etcd leaks, and pod metadata SSRF.
   - `cloud_serverless_lambda_audit`: Serverless API gateways, AWS S3 bucket permissions, and IAM token leaks.
   - `microservice_grpc_protobuf_audit`: gRPC reflection endpoints, Protobuf schema leaks, and HTTP/2 smuggling.
   - `oauth_jwt_sso_audit`: OAuth 2.0 misconfigurations, JWT `none` algorithm, and SSO callback vulnerabilities.
   - `websocket_realtime_audit`: WebSocket hijacking, unauthenticated WS endpoints, and message tampering.

3. **OWASP Top 10 & Injections (6 Templates)**:
   - `web_owasp_deep_audit`: Exhaustive DAST audit combining WhatWeb, Nuclei, Nikto, ZAP, and Wapiti.
   - `injection_sqli_nosqli_audit`: Deep parameter fuzzing for SQL, NoSQL, and blind injection.
   - `injection_xss_csrf_audit`: Reflected, stored, and DOM-based Cross-Site Scripting audits.
   - `injection_ssrf_xxe_audit`: Server-Side Request Forgery and XML External Entity audits.
   - `auth_access_control_audit`: IDOR, broken object-level authorization, and privilege escalation.
   - `file_upload_lfi_rfi_audit`: Unrestricted file uploads, Local/Remote File Inclusion, and path traversal.

4. **Infrastructure & Network (6 Templates)**:
   - `full_infrastructure_audit`: Network perimeter port probing, TLS ciphers, and network service CVEs.
   - `database_exposure_audit`: Publicly exposed MySQL, PostgreSQL, MongoDB, Redis, and ElasticSearch databases.
   - `remote_management_rdp_ssh_audit`: SSH, RDP, VNC, and Telnet management exposure and weak credentials.
   - `mail_dns_infrastructure_audit`: DNS zone transfer, SPF/DKIM/DMARC spoofing, and SMTP relay flaws.
   - `ssl_tls_cryptographic_audit`: Deprecated TLS 1.0/1.1, weak ciphers, Heartbleed, and POODLE flaws.
   - `network_firewall_bypass_audit`: HTTP request smuggling (CL.TE/TE.CL), proxy evasion, and cache poisoning.

5. **Recon, Secrets & Supply Chain (6 Templates)**:
   - `quick_recon_triage`: Rapid sub-minute reconnaissance pass for critical low-hanging fruit.
   - `cloud_secrets_exposure_audit`: Exposed `.git` repositories, `.env` files, and hardcoded API tokens.
   - `cicd_devops_pipeline_audit`: Jenkins script consoles, exposed SonarQube, and GitLab RCE vulnerabilities.
   - `subdomain_takeover_audit`: Dangling CNAMEs pointing to unclaimed GitHub Pages, S3, or Heroku apps.
   - `reverse_proxy_waf_bypass_audit`: Nginx alias traversal, X-Forwarded-For IP bypasses, and WAF evasion.
   - `internal_admin_panel_audit`: Exposed phpMyAdmin, Grafana, Kibana, Portainer, and cPanel consoles.

---

## 🛠️ 10. System Environment & Diagnostic Pre-flight Checks

The platform includes a built-in pre-flight diagnostic system to verify host tools, Docker container status, and local LLM availability:

```bash
# Run full system diagnostic
./start.sh check
# or
./start.sh doctor
```

### What `./start.sh check` Tests:
1. **Host Operating System**: Detects Kali Linux, Parrot Security OS, Fedora, Debian/Ubuntu, or Arch Linux.
2. **Native Host Binaries**: Checks `nmap`, `nuclei`, `nikto`, `whatweb`, `sqlmap`, `ffuf`, `sslyze`, `wapiti`, `zap` on `$PATH`.
3. **Curated MCP Container**: Checks if `pentest-backend:latest` exists and verifies tools baked inside the container.
4. **Local LLM Engine**: Checks Ollama CLI, service reachability on port 11434, and downloaded models (`qwen2.5:7b`).
5. **Tailored Distro Guidance**: Displays exact installation commands for your specific Linux distribution (`apt`, `dnf`, or `pacman`).

### Unified CLI Usage via `start.sh`
```bash
# Autonomous scan (LLM analyzes recon and chooses optimal template automatically):
./start.sh scan scanme.nmap.org --template auto

# List all 30 templates:
./start.sh templates

# Filter templates by category:
./start.sh templates --category "API & Cloud"

# Execute a specific template manually:
./start.sh scan target.com --template framework_django_audit -o audit_report.md

# Pre-flight diagnostic probe:
./start.sh probe scanme.nmap.org
```

