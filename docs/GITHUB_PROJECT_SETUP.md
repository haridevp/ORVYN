# 🛠️ GitHub Project Board Setup Guide

Follow these steps to create a Kanban-style Agile board on GitHub.

---

## Step 1: Create the Project Board

1. Go to your GitHub repo: `https://github.com/<your-org>/AI-Automated-Penetration-Testing`
2. Click the **"Projects"** tab → **"New project"**
3. Select **"Board"** template (Kanban)
4. Name it: `AI PenTest — Sprint Board`
5. Click **Create**

---

## Step 2: Add These Columns

| Column Name | Description |
|------------|-------------|
| 📥 **Backlog** | All items not yet in a sprint |
| 📝 **To Do** | Items committed for the current sprint |
| 🔄 **In Progress** | Actively being worked on |
| 👀 **In Review** | PR opened, awaiting review |
| ✅ **Done** | Merged and complete |
| ❌ **Blocked** | Waiting on dependency/decision |

---

## Step 3: Create Labels

Go to **Issues → Labels → New Label** and create these:

| Label | Color | Use For |
|-------|-------|---------|
| `epic: recon` | `#0052CC` | Reconnaissance tasks |
| `epic: vuln-scanner` | `#E11D48` | Vulnerability scanner tasks |
| `epic: ai-core` | `#7C3AED` | AI/ML model tasks |
| `epic: exploitation` | `#B45309` | Exploitation engine |
| `epic: reports` | `#047857` | Report generator |
| `epic: ui` | `#0891B2` | Dashboard/UI |
| `epic: infra` | `#6B7280` | Setup, CI/CD, DevOps |
| `type: user-story` | `#FCD34D` | Feature request / story |
| `type: bug` | `#EF4444` | Bug fix |
| `type: research` | `#8B5CF6` | Research spike |
| `priority: high` | `#DC2626` | High priority |
| `priority: medium` | `#F59E0B` | Medium priority |
| `priority: low` | `#10B981` | Low priority |

---

## Step 4: Create Milestones (as Sprints)

Go to **Issues → Milestones → New Milestone**:

| Milestone | Due Date |
|-----------|---------|
| Sprint 1 — Foundation | 09 Mar 2026 |
| Sprint 2 — Recon Complete | 23 Mar 2026 |
| Sprint 3 — Vuln Scanner | 06 Apr 2026 |
| Sprint 4 — Reports + Demo | 20 Apr 2026 |

---

## Step 5: Create Issues From Backlog

For each item in `docs/BACKLOG.md`:
1. Go to **Issues → New Issue**
2. Select the **User Story** template
3. Fill in title, description, acceptance criteria
4. Add appropriate **Labels**, **Milestone**, and **Assignee**
5. Add to the Project board in **Backlog** column
6. At sprint planning, move committed cards from **Backlog** to **To Do**

---

## Step 6: Automate the Board (Optional)

In the Project settings, enable these **automations**:
- PR opened → Move to **In Review**
- PR merged → Move to **Done**
- Issue closed → Move to **Done**

---

## 💡 Daily Workflow

```
Morning (async standup in chat):
  🟢 What did I do yesterday?
  🔵 What will I do today?
  🔴 Any blockers?

During work:
  → Move cards on the board as you progress
  → Commit with message: "feat(recon): add nmap port scanner #5"
  → Open PR when ready, link to issue with "Closes #5"

End of sprint:
  → Update SPRINTS.md with velocity and retrospective notes
  → Move uncompleted items back to Backlog
  → Plan next sprint
```

## Sprint View Guidance

Use the board as the sprint source of truth:
- `Backlog` stores all unscheduled issues
- `To Do` stores only the cards committed for the active sprint
- `In Progress` means coding or testing has started
- `In Review` means a PR is open and linked to the issue
- `Done` means merged into `develop`
- `Blocked` means work cannot continue without a decision or dependency

For each sprint card, keep these fields updated:
- story or issue number
- assignee
- sprint milestone
- priority label
- estimate in story points
- linked branch or PR
