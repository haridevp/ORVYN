# 👥 Team

> AI-Automated-Penetration-Testing | Final Year Project

---

## Members

| # | Name | GitHub | Role | Responsible Modules |
|---|------|--------|------|---------------------|
| 1 | vistanoop | @vistanoop | Full Stack | Backend API, Multi-Scanner Orchestration, Dashboard |
| 2 | _(Add Name)_ | @username | Recon & Scanning | Reconnaissance, Vuln Scanner |
| 3 | _(Add Name)_ | @username | Exploitation | Exploitation Engine |
| 4 | _(Add Name)_ | @username | Frontend & Reports | Dashboard, Report Generator |

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
