# 📋 Product Backlog

> AI-Automated-Penetration-Testing | Updated: Feb 2026

---

## 📌 How to Use This Backlog

- Items are sorted by **priority** (High → Low)
- Each item has a size estimate using **story points** (1 = tiny, 5 = small, 8 = medium, 13 = large)
- Pick items from the top during Sprint Planning
- Create a **GitHub Issue** for each item you pick up, then link it to the Project Board

---

## 🔴 Epic 1: Project Setup & Infrastructure

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-001 | As a team, we want a GitHub repo with GitHub Actions CI/CD so that code is always tested | 5 | 🔴 High | 🔄 In Progress |
| US-002 | As a developer, I want a `docker-compose.yml` for FastAPI + Redis + PostgreSQL + ChromaDB so I can spin up the full stack locally | 8 | 🔴 High | 🔲 To Do |
| US-003 | As a developer, I want a defined project folder structure (frontend/, backend/, ai/, docs/) | 2 | 🔴 High | ✅ Done |
| US-004 | As a developer, I want pre-commit hooks (black, flake8, prettier) for code quality | 3 | 🟡 Medium | 🔲 To Do |

---

## 🔴 Epic 2: Backend API (FastAPI)

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-005 | As a user, I want a `POST /scans` endpoint to trigger a new pentest scan | 5 | 🔴 High | 🔲 To Do |
| US-006 | As a user, I want a `GET /scans/{id}` endpoint to check scan status and results | 3 | 🔴 High | 🔲 To Do |
| US-007 | As a user, I want JWT-based authentication on all API endpoints | 5 | 🔴 High | 🔲 To Do |
| US-008 | As a developer, I want Celery workers to handle long-running scans asynchronously via Redis | 8 | 🔴 High | 🔲 To Do |
| US-009 | As a developer, I want scan results persisted to PostgreSQL with proper schema/migrations | 5 | 🔴 High | 🔲 To Do |

---

## 🔴 Epic 3: Reconnaissance & Scanning

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-010 | As a user, I want Nmap integration so I can discover open ports and services on a target | 8 | 🔴 High | 🔲 To Do |
| US-011 | As a user, I want OS fingerprinting via Nmap so I know the target OS | 5 | 🔴 High | 🔲 To Do |
| US-012 | As a user, I want OWASP ZAP integration for web application vulnerability scanning (SQLi, XSS) | 8 | 🔴 High | 🔲 To Do |
| US-013 | As a user, I want scan results (Nmap + ZAP) combined into a unified JSON structure | 5 | 🟡 Medium | 🔲 To Do |

---

## 🟡 Epic 4: AI/ML Core (LangChain + Ollama + ChromaDB)

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-014 | As a developer, I want Ollama running a local LLM (e.g. Llama 3 / Mistral) to analyze scan results | 8 | 🔴 High | 🔲 To Do |
| US-015 | As a developer, I want a LangChain pipeline that takes scan output and generates a threat analysis | 13 | 🔴 High | 🔲 To Do |
| US-016 | As a developer, I want CVE/exploit knowledge ingested into ChromaDB for RAG-based retrieval | 8 | 🔴 High | 🔲 To Do |
| US-017 | As a user, I want the AI to suggest the most likely exploits for discovered vulnerabilities using RAG | 13 | 🟡 Medium | 🔲 To Do |
| US-018 | As a developer, I want AI model evaluation metrics (response relevance, accuracy) documented | 5 | 🟡 Medium | 🔲 To Do |

---

## 🟡 Epic 5: Report Generator

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-019 | As a user, I want an auto-generated PDF pentest report after each scan | 8 | 🔴 High | 🔲 To Do |
| US-020 | As a user, I want the report to include executive summary, technical findings, and CVSS scores | 5 | 🔴 High | 🔲 To Do |
| US-021 | As a user, I want AI-generated remediation recommendations included in the report | 8 | 🟡 Medium | 🔲 To Do |
| US-022 | As a user, I want reports stored in PostgreSQL and downloadable from the dashboard | 3 | 🟡 Medium | 🔲 To Do |

---

## 🔵 Epic 6: Frontend Dashboard (React + Tailwind CSS)

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-023 | As a user, I want a React dashboard where I can enter a target and start a scan | 8 | 🟡 Medium | 🔲 To Do |
| US-024 | As a user, I want real-time scan progress shown using WebSockets or polling | 5 | 🟡 Medium | 🔲 To Do |
| US-025 | As a user, I want a vulnerability table on the dashboard with severity colour coding (Tailwind) | 5 | 🟡 Medium | 🔲 To Do |
| US-026 | As a user, I want to view, filter, and download past scan reports from the dashboard | 5 | 🟡 Medium | 🔲 To Do |
| US-027 | As a user, I want login/register pages with JWT auth integration on the frontend | 5 | 🔴 High | 🔲 To Do |

---

## Priority Legend

| Symbol | Priority |
|--------|---------|
| 🔴 | High — Must have |
| 🟡 | Medium — Should have |
| 🔵 | Nice to have |

## Status Legend

| Symbol | Status |
|--------|--------|
| 🔲 | To Do |
| 🔄 | In Progress |
| ✅ | Done |
| ❌ | Blocked |
