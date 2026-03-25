# 🤝 Contributing Guide

> AI-Automated-Penetration-Testing | Final Year Project

---

## 🚀 Getting Started

1. Clone the repo:
   ```bash
   git clone https://github.com/<your-org>/AI-Automated-Penetration-Testing.git
   cd AI-Automated-Penetration-Testing
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux/Mac
   venv\Scripts\activate      # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r src/backend/requirements.txt
   ```

---

## 🌿 Branching & Workflow

1. **Always branch off `develop`**, never `main`:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout -b feature/your-feature-name
   ```

2. **Branch naming**:
   - `feature/<description>` — new feature
   - `fix/<description>` — bug fix
   - `docs/<description>` — documentation
   - `research/<description>` — spike/research

3. **Commit messages** (follow this format):
   ```
   type(scope): short description #issue-number

   Examples:
   feat(recon): add nmap port scanner #5
   fix(vuln-scanner): handle null CVE response #12
   docs(readme): update installation steps
   ```

---

## 📤 Submitting a PR

1. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Open a PR on GitHub from your branch -> `develop`
3. Fill in the **PR template** completely
4. Assign at least **1 reviewer** from the team
5. Add the appropriate **labels** and **milestone**
6. Link to the related **GitHub Issue** using `Closes #N`

---

## 🔍 Code Review Rules

- All PRs need at least **1 approval** before merging
- Reviewer should check: correctness, style, tests, edge cases
- Never merge your own PR (unless it's trivial, e.g., docs)
- Be respectful in review comments 🙏

---

## 🧪 Testing

- Write tests for every new feature in `tests/`
- Run tests before pushing:
  ```bash
  pytest tests/
  ```
- CI runs on `develop` pushes and pull requests
- Deployment validation runs after a reviewed merge into `main`

---

## 📋 Picking Up Tasks

1. Go to the **GitHub Project Board**
2. Pick an issue from **To Do** in the active sprint view
3. Assign yourself to the issue
4. Move the card to **In Progress**
5. Create a branch and start coding!
