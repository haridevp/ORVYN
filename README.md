# ORVYN: Offensive Risk and Vulnerability Intelligence Network

> **Autonomous Multi-Stage Penetration Testing & DAST Intelligence Platform**  
> *Final Year Engineering Capstone | Academic & Production Security Research*

[![CI/CD Pipeline](https://github.com/haridevp/ORVYN/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/haridevp/ORVYN/actions)
[![Deploy Dashboard to GitHub Pages](https://github.com/haridevp/ORVYN/actions/workflows/pages.yml/badge.svg)](https://github.com/haridevp/ORVYN/actions/workflows/pages.yml)
[![License: MIT](https://img.shields.io/badge/License-Academic_Research-blue.svg)](#license)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com)
[![React 18](https://img.shields.io/badge/Frontend-React_18_%2B_Vite-61dafb.svg)](https://react.dev)

---

## Overview

**ORVYN** is an autonomous offensive security platform engineered to transcend static, uncoordinated vulnerability scanners. By orchestrating a coordinated **5-phase autonomous reconnaissance and assessment pipeline**, ORVYN pairs live perimeter fingerprinting with local Large Language Models (`Qwen 2.5:7b`) to dynamically select targeted vulnerability assessment templates and verifies all findings against an authoritative 5,000+ vector-embedded security knowledge base (**ChromaDB**).

📖 **[Read the Full Technical Architecture & System Specifications](docs/TECHNICAL_DETAILS.md)**

---

## Key Capabilities & Innovations

### 1. Redamon-Inspired Interactive Recon Pipeline Workflow
* **Circuit-Bus Node Graph**: High-tech visual representation of the entire offensive pipeline modeled after the Redamon reconnaissance architecture.
* **Three Functional Bands**:
  * **Upper Data Band**: Live data entity pills (`Domain`, `Subdomain`, `IP`, `Port`, `Service`, `BaseURL`, `Endpoint`, `CVE`).
  * **Center Tool Band**: 9 sequential stages featuring interactive tool cards (`Target Input` ➔ `Discovery` ➔ `OSINT` ➔ `Port Scanning` ➔ `HTTP Probing` ➔ `Resource Enum` ➔ `JS Recon` ➔ `Vulnerability Scanning` ➔ `Analysis & AI`).
  * **Lower Data Band**: Enriched entities (`DNSRecord`, `Certificate`, `Header`, `Technology`, `Parameter`, `Secret`, `ExternalDomain`, `Vulnerability`, `MitreData`, `Capec`).
* **Interactive Tool Controls**: Instant enable/disable switches on each tool node, click-to-highlight data bus trace lines, and standalone "Run Partial Recon" triggers.
* **Starved Node Detection & Amber Warnings**: If required inputs lack an active producer (e.g. `BaseURL` with probing tools disabled), nodes pulse red and downstream consumers display warning alerts (`⚠️`).

### 2. Autonomous 5-Phase Assessment Lifecycle
1. **Phase 1: Perimeter Reconnaissance & Fingerprinting**: Live port discovery, service version detection, server banners, SSL/TLS cryptographic testing (`Nmap`, `WhatWeb`, `SSLyze`, `Nikto`, `OWASP ZAP`).
2. **Phase 2: LLM Validation & Dynamic Template Selection**: Local AI (`Qwen 2.5` via Ollama) evaluates discovered web frameworks and open ports to automatically select from 30 specialized assessment templates (e.g., `api-security-audit`, `cve-critical-rce`, `cloud-perimeter`).
3. **Phase 3: Targeted Tool Execution**: Runs targeted engines (`Nuclei` with dynamic tags, `Wapiti` for parameter auditing, `SQLMap` for database injections, `Ffuf` for directory fuzzing).
4. **Phase 4: Security RAG Knowledge Base Triage**: Vector similarity lookup over 5,000+ chunks (OWASP Top 10:2025, NIST NVD, MITRE ATT&CK & CAPEC) to validate severity tiers and filter false positives.
5. **Phase 5: Automated Correlation & Deduplication**: Groups corroborated vulnerabilities across multiple tools and synthesizes unified reports.

### 3. Futuristic Cyber-Deck User Interface
* **Sleek Aesthetic**: Deep obsidian carbon palette (`#06070c`) with luminous cyan/emerald neon telemetry rails and responsive glassmorphism.
* **Live System Metrics**: Real-time streaming logs, executive risk scorecards, severity distribution donuts, and live-finding feeds.
* **Integrated Command Matrix**: `Ctrl + K` global command palette for rapid navigation, host scoping, and template filtering.

---

## System Architecture

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                    REACT 18 + VITE + TAILWIND FRONTEND                     │
│  [Redamon Workflow Graph]  [Futuristic Cyber-Deck]  [Live Terminal Console]│
└─────────────────────────────────────┬──────────────────────────────────────┘
                                      │ REST API / Live Polling
┌─────────────────────────────────────▼──────────────────────────────────────┐
│                        FASTAPI ORCHESTRATION BACKEND                       │
│  - Scan Job Manager & Non-Blocking Subprocess Pool                         │
│  - Scope Enforcement Engine (In-Scope Allowlist / Out-of-Scope Exclusions) │
│  - Correlated Finding & Severity Aggregation Engine                        │
└──────────────┬──────────────────────┬──────────────────────┬───────────────┘
               │                      │                      │
┌──────────────▼──────────────┐┌──────▼──────────────┐┌──────▼───────────────┐
│     MODULE 1: TOOLCHAIN     ││   MODULE 2: LLM     ││    MODULE 3: RAG     │
│ - Nmap (Ports & Scripts)    ││ - Qwen 2.5:7b       ││ - ChromaDB Vector DB │
│ - WhatWeb & SSLyze          ││ - 30 Dynamic Pentest││ - 5,000+ Curated     │
│ - Nikto & OWASP ZAP         ││   Templates         ││   OWASP/CVE/CWE Docs │
│ - Nuclei, Wapiti, SQLMap    ││ - Heuristic Rule    ││ - Authoritative      │
│ - Ffuf (Fuzzing)            ││   Fallback Engine   ││   Citation Matcher   │
└─────────────────────────────┘└─────────────────────┘└──────────────────────┘
```

---

## Supported Security Scanners

| Engine | Version | Mode | Core Capabilities |
|---|---|---|---|
| **Nmap** | 7.93+ | Active | Port scanning, service version detection, OS fingerprinting |
| **WhatWeb** | 0.5.5 | Active/Passive | CMS, web server, and technology stack fingerprinting |
| **SSLyze** | 5.2.0 | Active | TLS/SSL cipher suite auditing, certificate expiration, Heartbleed |
| **Nikto** | 2.5.0 | Active | Web server misconfigurations, dangerous CGIs, outdated software |
| **Nuclei** | 3.3.0 | Active | 9,000+ YAML template checks for CVEs, zero-days, and exposures |
| **OWASP ZAP** | 2.15 | Active | Baseline web application scanning, OWASP Top 10 vulnerabilities |
| **Wapiti** | 3.1.8 | Active | Parameter auditing for XSS, SQLi, SSRF, and file inclusions |
| **SQLMap** | 1.8 | Active | Automated SQL injection verification and database testing |
| **FFuf** | 2.1 | Active | High-speed directory, hidden file, and `.env` fuzzing |

---

## Quick Start Guide

### 1. Docker Compose (Full Stack)

Launch the complete containerized stack (FastAPI backend, React dashboard, PostgreSQL, Redis):

```bash
# Clone the repository
git clone https://github.com/haridevp/ORVYN.git
cd ORVYN

# Start all core services in background
docker compose up -d

# Check running services
docker compose ps
```

* **Frontend Dashboard**: `http://localhost:5173`
* **FastAPI Interactive Docs**: `http://localhost:8000/docs`
* **Health Endpoint**: `http://localhost:8000/api/health`

### 2. Standalone CLI Usage

The repository includes a standalone Python CLI (`./start.sh` or `cli.py`):

```bash
# Autonomous assessment with AI template selection
./start.sh scan example.com --template auto

# Targeted assessment with custom scanner subset
./start.sh scan example.com --scanners nmap,whatweb,nuclei

# List all 30 vulnerability assessment templates
./start.sh templates

# System and toolchain diagnostics check
./start.sh check

# Query status of an existing scan from running backend
./start.sh status <scan_id> --api http://localhost:8000
```

---

## Project Documentation

* **[Technical Details & System Architecture](docs/TECHNICAL_DETAILS.md)**: Deep dive into subprocess management, RAG embeddings, and the Redamon graph specification.
* **[Agile Backlog](docs/BACKLOG.md)**: User stories, epics, and planned milestones.
* **[Sprint Tracking](docs/SPRINTS.md)**: Sprint retrospectives and delivery velocity.
* **[Product Roadmap](docs/ROADMAP.md)**: Multi-semester research phases and capabilities timeline.
* **[Team Roles & Responsibilities](docs/TEAM.md)**: Engineering team organization.

---

## Contributing

Please review [CONTRIBUTING.md](CONTRIBUTING.md) for branch management, commit conventions, and testing guidelines.

---

## License

Academic and Research Open-Source Project. All rights reserved.
