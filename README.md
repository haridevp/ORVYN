# 🔐 AI-Automated-Penetration-Testing

> **Final Year Project** | Semester 6–8 | Team of 4

An AI-powered penetration testing framework that automates reconnaissance, vulnerability scanning, exploitation, and report generation using machine learning models.

---

## 📋 Project Status

| Sprint | Period | Status |
|--------|--------|--------|
| Sprint 1 | Sem 6 – Week 1–2 | 🔄 In Progress |
| Sprint 2 | Sem 6 – Week 3–4 | ⏳ Planned |
| Sprint 3 | Sem 6 – Week 5–6 | ⏳ Planned |

🗂️ **[View Full Backlog](docs/BACKLOG.md)** | 🗓️ **[Sprint Plan](docs/SPRINTS.md)** | 🗺️ **[Roadmap](docs/ROADMAP.md)** | 👥 **[Team](docs/TEAM.md)**

---

## 🧩 Modules

| Module | Description | Owner |
|--------|-------------|-------|
| 🔍 **Reconnaissance** | Automated network/host discovery | TBD |
| 🛡️ **Vulnerability Scanner** | AI-assisted CVE detection | TBD |
| 💥 **Exploitation Engine** | Automated payload generation & execution | TBD |
| 🤖 **AI/ML Core** | Models for decision-making & prioritization | TBD |
| 📊 **Report Generator** | Auto-generate pentest reports | TBD |
| 🖥️ **Dashboard / UI** | Web UI for control & visualization | TBD |

---

## 🚀 Tech Stack

### Frontend
- **React.js** — Component-based UI with dynamic state management
- **Tailwind CSS** — Utility-first CSS for rapid, responsive styling

### Backend
- **FastAPI** — High-performance async Python REST API
- **Celery + Redis** — Distributed task queue for long-running scans

### Database & Storage
- **PostgreSQL** — Relational data (users, scans, vulnerabilities)
- **ChromaDB** — Vector store for RAG-based knowledge retrieval

### AI/ML & Security
- **LangChain + Ollama** — Local LLM orchestration for behavioral analysis
- **Nmap** — Network scanning and reconnaissance
- **OWASP ZAP** — Web application vulnerability scanning

### DevOps
- **CI/CD**: GitHub Actions

---

## 👥 Team

| Member | Role |
|--------|------|
| Member 1 | Project Lead / AI Core |
| Member 2 | Reconnaissance & Scanning |
| Member 3 | Exploitation Engine |
| Member 4 | UI / Dashboard / Reports |

---

## 📁 Project Structure

```
AI-Automated-Penetration-Testing/
├── .github/
│   ├── ISSUE_TEMPLATE/       # Issue templates for tasks, bugs, stories
│   └── pull_request_template.md
├── docs/
│   ├── BACKLOG.md            # Full product backlog
│   ├── SPRINTS.md            # Sprint history & planning
│   ├── ROADMAP.md            # Semester-wise roadmap
│   ├── TEAM.md               # Team roles & responsibilities
│   └── GITHUB_PROJECT_SETUP.md
├── src/                      # Source code (to be added)
├── tests/                    # Unit & integration tests
└── README.md
```

---

## 🧑‍💻 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to pick up tasks, branch naming, and PR rules.

---

## 📄 License

Academic project — All rights reserved.