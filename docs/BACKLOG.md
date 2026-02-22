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
| US-001 | As a team, we want a configured GitHub repo with CI/CD so that code is always tested | 5 | 🔴 High | 🔄 In Progress |
| US-002 | As a developer, I want a dev environment setup guide so I can start coding quickly | 3 | 🔴 High | 🔲 To Do |
| US-003 | As a team, we want a defined folder structure so that code is organized | 2 | 🔴 High | 🔲 To Do |
| US-004 | As a developer, I want pre-commit hooks for linting so that code quality is maintained | 3 | 🟡 Medium | 🔲 To Do |

---

## 🔴 Epic 2: Reconnaissance Module

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-005 | As a user, I want to scan a target IP/domain for open ports so that I can identify attack surface | 8 | 🔴 High | 🔲 To Do |
| US-006 | As a user, I want OS fingerprinting on discovered hosts so that I know what I'm dealing with | 5 | 🔴 High | 🔲 To Do |
| US-007 | As a user, I want subdomain enumeration so that hidden attack vectors are found | 5 | 🟡 Medium | 🔲 To Do |
| US-008 | As a user, I want service/version detection so that specific vulnerabilities can be matched | 5 | 🔴 High | 🔲 To Do |
| US-009 | As a user, I want recon results saved to a structured format (JSON/DB) for later use | 3 | 🟡 Medium | 🔲 To Do |

---

## 🟡 Epic 3: Vulnerability Scanner

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-010 | As a user, I want CVE lookup for detected service versions so that known vulns are flagged | 8 | 🔴 High | 🔲 To Do |
| US-011 | As a user, I want severity scoring (CVSS) displayed for each vulnerability | 5 | 🟡 Medium | 🔲 To Do |
| US-012 | As a user, I want AI-based vulnerability prioritization so that critical issues are addressed first | 13 | 🔴 High | 🔲 To Do |
| US-013 | As a user, I want web application scanning (SQLi, XSS, IDOR) so that web vulns are caught | 8 | 🟡 Medium | 🔲 To Do |

---

## 🟡 Epic 4: AI/ML Core

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-014 | As a developer, I want a dataset of CVEs/exploits for model training | 8 | 🔴 High | 🔲 To Do |
| US-015 | As a developer, I want a trained classifier to prioritize vulnerabilities by exploitability | 13 | 🔴 High | 🔲 To Do |
| US-016 | As a user, I want the AI to suggest the best exploit to run based on scan results | 13 | 🟡 Medium | 🔲 To Do |
| US-017 | As a developer, I want model evaluation metrics (accuracy, F1) documented | 5 | 🟡 Medium | 🔲 To Do |

---

## 🟠 Epic 5: Exploitation Engine

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-018 | As a user, I want Metasploit integration so that exploits can be launched automatically | 13 | 🔴 High | 🔲 To Do |
| US-019 | As a user, I want payload generation based on target OS/service | 8 | 🟡 Medium | 🔲 To Do |
| US-020 | As a user, I want post-exploitation data collection (credentials, files) | 8 | 🟡 Medium | 🔲 To Do |
| US-021 | As a user, I want a safe sandbox/lab mode so that exploitation is only run in controlled env | 5 | 🔴 High | 🔲 To Do |

---

## 🔵 Epic 6: Report Generator

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-022 | As a user, I want an auto-generated PDF/HTML pentest report after each scan | 8 | 🔴 High | 🔲 To Do |
| US-023 | As a user, I want the report to include executive summary + technical details | 5 | 🟡 Medium | 🔲 To Do |
| US-024 | As a user, I want remediation recommendations in the report for each vuln | 5 | 🟡 Medium | 🔲 To Do |

---

## 🟢 Epic 7: Dashboard / UI

| ID | User Story | Points | Priority | Status |
|----|-----------|--------|----------|--------|
| US-025 | As a user, I want a web dashboard to start/stop scans with one click | 8 | 🟡 Medium | 🔲 To Do |
| US-026 | As a user, I want real-time scan progress visible on the dashboard | 5 | 🟡 Medium | 🔲 To Do |
| US-027 | As a user, I want to view all past scan results and reports from the dashboard | 5 | 🟡 Medium | 🔲 To Do |
| US-028 | As a user, I want user authentication on the dashboard so only authorized users access it | 5 | 🔴 High | 🔲 To Do |

---

## Priority Legend

| Symbol | Priority |
|--------|---------|
| 🔴 | High — Must have |
| 🟡 | Medium — Should have |
| 🟠 | Low — Could have |
| 🔵 | Nice to have |

## Status Legend

| Symbol | Status |
|--------|--------|
| 🔲 | To Do |
| 🔄 | In Progress |
| ✅ | Done |
| ❌ | Blocked |
