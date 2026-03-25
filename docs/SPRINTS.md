# 🏃 Sprint History & Planning

> AI-Automated-Penetration-Testing | 2-week sprints

---

## GitHub Kanban Usage

Active sprint execution is tracked in GitHub Projects using this flow:
- `Backlog` for unscheduled issues
- `To Do` for sprint-committed cards
- `In Progress` for active implementation
- `In Review` for PR-linked cards awaiting approval
- `Done` for work merged into `develop`
- `Blocked` for dependency or decision blockers

Each sprint item should include:
- GitHub issue number
- user story ID
- assignee
- story points
- milestone
- linked branch or PR
- card status on the Kanban board

---

## 📐 Sprint Template

Copy and fill this for each new sprint:

```
### Sprint N — [Start Date] to [End Date]
**Goal**: [One sentence describing what this sprint delivers]
**Scrum Master**: [Name]

| Issue # | Story ID | Description | Assignee | Points | Status |
|---------|----------|-------------|----------|--------|--------|
| #X      | US-XXX   | ...         | @user    | X      | 🔲/🔄/✅/❌ |

**Velocity**: X points completed / X points planned
**Retrospective Notes**:
- ✅ Went well: ...
- 🔧 To improve: ...
- ❌ Blocked: ...

**Kanban Details**:
- Board view: Active Sprint
- Cards moved from `Backlog` to `To Do` during sprint planning
- Each issue must link to its branch or PR before moving to `In Review`
```

---

## 🟢 Sprint 1 — 24 Feb 2026 to 09 Mar 2026

**Goal**: Set up the project foundation — repo, dev environment, CI/CD, and basic folder structure  
**Scrum Master**: Member 1

| Issue # | Story ID | Description | Assignee | Points | Status |
|---------|----------|-------------|----------|--------|--------|
| #1 | US-001 | Configure GitHub repo with GitHub Actions CI | Member 1 | 5 | ✅ Done |
| #2 | US-002 | Write dev environment setup guide (README) | Member 2 | 3 | ✅ Done |
| #3 | US-003 | Define project folder structure | Member 1 | 2 | ✅ Done |
| #4 | US-005 | Nmap integration for port scanning | Member 2 | 8 | 🔄 In Progress |

**Velocity**: 10 / 18 points  
**Retrospective Notes**:
- ✅ Went well: repo structure, CI/CD workflow, and Docker base setup were established early
- 🔧 To improve: issue ownership and PR linking should be updated more consistently in the board
- ❌ Blocked: scanner integration still depends on the next technical spike

**Kanban Details**:
- Cards committed to Sprint 1 were moved to `To Do` at planning time
- Completed setup work is in `Done`
- Recon implementation card remains in `In Progress` while integration code is added

---

## ⏳ Sprint 2 — 10 Mar 2026 to 23 Mar 2026

**Goal**: Complete reconnaissance module (port scan, OS detect, service detect)

| Issue # | Story ID | Description | Assignee | Points | Status |
|---------|----------|-------------|----------|--------|--------|
| #5 | US-006 | OS fingerprinting | Member 2 | 5 | 🔲 To Do |
| #6 | US-008 | Service/version detection | Member 2 | 5 | 🔲 To Do |
| #7 | US-009 | Save recon results to JSON/DB | Member 3 | 3 | 🔲 To Do |
| #8 | US-004 | Add pre-commit hooks (flake8/black) | Member 1 | 3 | 🔲 To Do |

**Velocity**: — / 16 points

**Kanban Details**:
- Move only ready recon tasks into `To Do`
- Link each recon issue to its feature branch before review

---

## ⏳ Sprint 3 — 24 Mar 2026 to 06 Apr 2026

**Goal**: Basic vulnerability scanner (CVE lookup + CVSS scoring)

| Issue # | Story ID | Description | Assignee | Points | Status |
|---------|----------|-------------|----------|--------|--------|
| #9 | US-010 | CVE lookup for detected service versions | Member 2 | 8 | 🔲 To Do |
| #10 | US-011 | CVSS severity scoring display | Member 4 | 5 | 🔲 To Do |
| #11 | US-014 | Begin dataset collection for AI model | Member 1 | 8 | 🔲 To Do |

**Velocity**: — / 21 points

**Kanban Details**:
- Security scanner tasks remain in `Backlog` until recon outputs are stable
- Review cards should include evidence screenshots or sample JSON output

---

## ⏳ Sprint 4 — 07 Apr 2026 to 20 Apr 2026

**Goal**: Basic report generator + semester 6 demo prep

| Issue # | Story ID | Description | Assignee | Points | Status |
|---------|----------|-------------|----------|--------|--------|
| #12 | US-022 | Auto-generate PDF/HTML pentest report | Member 4 | 8 | 🔲 To Do |
| #13 | US-023 | Report: executive summary + technical details | Member 4 | 5 | 🔲 To Do |
| #14 | US-007 | Subdomain enumeration | Member 2 | 5 | 🔲 To Do |

**Velocity**: — / 18 points

**Kanban Details**:
- Demo-related cards should be tagged with sprint milestone and `priority: high`
- Report tasks should link generated artifacts in the issue comments before closure

---

## 📊 Velocity Tracker

| Sprint | Planned Points | Completed Points | Velocity |
|--------|---------------|-----------------|---------|
| Sprint 1 | 18 | — | — |
| Sprint 2 | 16 | — | — |
| Sprint 3 | 21 | — | — |
| Sprint 4 | 18 | — | — |

> **Average velocity** will be calculated after Sprint 2 and used to plan Sem 7.
