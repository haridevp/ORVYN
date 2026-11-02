# 👥 Team

> AI-Automated-Penetration-Testing | Final Year Project

---

### Project Guide & Corresponding Author
* **Dr. Neethu M R\*** (`mr_neethu@cb.amrita.edu`), Assistant Professor (Sr. Gd.), Department of Computer Science and Engineering, School of Computing, Amrita Vishwa Vidyapeetham, Coimbatore.

## Student Members (Team 37)

| # | Register Number | Student Name | Institutional Email | Role | Responsible Modules |
|---|-----------------|--------------|---------------------|------|---------------------|
| 1 | `CB.SC.U4CSE23417` | Haridev P | `cb.sc.u4cse23417@cb.students.amrita.edu` | Lead Architect & Full Stack | Overall System Architecture, Non-Blocking Orchestration, Recon Pipeline UI, Docker & Timeout Guards |
| 2 | `CB.SC.U4CSE23440` | Reenu L K | `cb.sc.u4cse23440@cb.students.amrita.edu` | Reconnaissance & Security Scanning | Nmap, SSLyze, Nikto Parsers, CVE Normalization & CVSS Scoring, Deduplication Logic |
| 3 | `CB.SC.U4CSE23459` | Anoop K | `cb.sc.u4cse23459@cb.students.amrita.edu` | Backend & Secondary Toolchain | Nuclei Template Mapping, SQLMap & FFuf Triggering, Report Generator & FastAPI Endpoints |
| 4 | `CB.SC.U4CSE23653` | Shruthilaya A V | `cb.sc.u4cse23653@cb.students.amrita.edu` | AI & Security Knowledge Engineer | ChromaDB Vector Database Indexing (5k+ chunks), RAG Triage Pipeline, Ollama LLM Prompting |

---

## 🧭 Agile Roles

| Role | Assigned To |
|------|------------|
| **Scrum Master** | Member 1 (rotate each sprint) |
| **Product Owner** | Member 1 |
| **Developer** | All members |

---

## 📅 Ceremonies

| Ceremony | Frequency | Duration | Description |
|----------|-----------|----------|-------------|
| **Sprint Planning** | Every 2 weeks | 1 hour | Plan the next sprint's tasks |
| **Daily Standup** | Daily (async via WhatsApp/Discord) | 5 min | What did you do? What will you do? Blockers? |
| **Sprint Review** | Every 2 weeks | 30 min | Demo what was built |
| **Retrospective** | Every 2 weeks | 30 min | What went well? What to improve? |

---

## 🌿 Git Branching Strategy

```
main          ← stable, reviewed, deployment-ready
│
├── develop   ← integration branch (merge PRs here)
│   ├── feature/recon-nmap-scan      (Member 2)
│   ├── feature/vuln-scanner-cve     (Member 2)
│   ├── feature/exploit-engine       (Member 3)
│   ├── feature/ai-model-training    (Member 1)
│   ├── feature/dashboard-ui         (Member 4)
│   └── fix/bug-description          (anyone)
```

### Branch Naming Convention
- `feature/<short-description>` — new feature
- `fix/<short-description>` — bug fix
- `docs/<short-description>` — documentation
- `research/<short-description>` — research spike

### PR Rules
1. All PRs go to `develop`, never directly to `main`
2. At least **1 reviewer** must approve before merging
3. Link the GitHub issue in your PR description
4. PR template must be filled out completely
