# AI-Automated-Penetration-Testing

> Final Year Project | Semester 6-8 | Team of 4

An AI-assisted penetration testing platform that coordinates scan requests, asynchronous worker execution, and validation-ready reporting. The current repository contains the project foundation, delivery workflow, and API proof-of-architecture for the larger system planned in the review deck.

[Full Backlog](docs/BACKLOG.md) | [Sprint Plan](docs/SPRINTS.md) | [Roadmap](docs/ROADMAP.md) | [Team](docs/TEAM.md)

## Current Status

Implemented in this repository today:
- **Multi-scanner orchestration API** (`/scan/start`, `/scan/status/{id}`, `/scan/results/{id}`, `/scan/{id}`): fans a scan out to Nuclei, ZAP, and Nikto concurrently, tracks per-scanner status, and never lets one scanner's failure sink the job
- **Result normalizer + correlation engine**: de-duplicates findings reported by multiple tools, raises confidence when tools corroborate each other, and flags conflicting severity ratings
- Each scanner wrapper (`src/backend/scanners/`) calls the real binary via subprocess if it's installed, and falls back to realistic simulated findings otherwise - so the API/UI/correlation engine are exercised end-to-end even without Nuclei/ZAP/Nikto installed locally
- Findings are enriched with CWE/OWASP Top 10:2025 references (`src/backend/references.py`)
- **React + Tailwind dashboard** (`frontend/`): scan form, live per-scanner progress, severity distribution, consolidated/correlated findings with corroboration and conflicting-severity indicators, and per-scanner raw results - with a demo-data fallback when no backend is reachable
- `security_rag_engine` service: Module 3/4 RAG pipeline, historical scan memory, and MCP bridge scaffolding
- Celery worker skeleton for asynchronous scan execution, Dockerfiles for backend/worker, `docker-compose.yml` with backend/worker/Redis/Postgres and an opt-in OWASP Juice Shop demo target
- GitHub Actions: CI on `develop`/PRs, deployment validation on merge-to-`main`, and a GitHub Pages deploy workflow for the dashboard
- Agile planning artifacts: backlog, sprint board guidance, roadmap, team roles, and issue templates

Planned next layers:
- Real Nuclei/ZAP/Nikto binaries wired into CI/Docker (wrappers already support it - see `src/backend/scanners/`)
- Additional scanner coverage (OpenVAS) and MCP tool integration
- RAG-grounded AI triage wired into the dashboard's consolidated findings view
- Authentication, role-based access, and report export

## Modules

| Module | Status | Notes |
|--------|--------|-------|
| Reconnaissance | Planned | Nmap integration tracked in backlog |
| Multi-Scanner Vulnerability Assessment | Implemented | Nuclei/ZAP/Nikto orchestration, correlation engine, unified finding schema |
| AI Validation / RAG | In Progress | `security_rag_engine` triage + history pipeline implemented; not yet wired into the dashboard |
| Reporting | In Progress | Report preview endpoint and result schema stub added |
| Backend API | Implemented | FastAPI multi-scanner job orchestration + legacy architecture-proof endpoints |
| Queue / Worker | Implemented Foundation | Celery task skeleton present; scan orchestration currently runs via async FastAPI background tasks |
| Dashboard / UI | Implemented | React/Tailwind multi-scanner dashboard, deployable to GitHub Pages |
| DevOps | Implemented Foundation | Docker Compose, GitHub Actions CI/CD, GitHub Pages deploy |

## Tech Stack

Current repo:
- FastAPI for API routing and multi-scanner job orchestration
- React, TypeScript, Vite, and Tailwind CSS for the dashboard
- Celery with Redis for asynchronous execution
- PostgreSQL container for persistence layer setup
- Docker Compose for local orchestration
- GitHub Actions for CI/CD and GitHub Pages deployment

Planned integration stack:
- LangChain, Ollama, and ChromaDB for validation and retrieval (scaffolded in `security_rag_engine`)
- OpenVAS for network/infrastructure coverage
- MCP-based tool integration (HexStrike/Vorota/RedaMon - under evaluation)

## Workflow

- Feature and docs branches are merged into `develop`
- CI runs on `develop` pushes and pull requests
- Validated changes are merged from `develop` into `main`
- Deployment validation runs after the merge to `main`

## API Proof

Current backend endpoints:
- `GET /`
- `GET /health`
- `GET /architecture/proof`
- `POST /scans` / `GET /scans/{scan_id}` / `GET /reports/{scan_id}` (legacy single-scanner stub)
- `POST /scan/start` - start a multi-scanner job (`target`, `scanners`, `profile`)
- `GET /scan/status/{scan_id}` - per-scanner progress + overall status
- `GET /scan/results/{scan_id}` - raw findings, correlated findings, severity distribution
- `GET /scan/{scan_id}` - scan summary

## Running Locally

Backend:
```bash
python -m venv venv && source venv/bin/activate
pip install -r src/backend/requirements.txt
cd src/backend && uvicorn main:app --reload
```

Dashboard:
```bash
cd frontend
npm install
npm run dev   # http://localhost:5173, talks to http://localhost:8000 by default
```

Point the dashboard at a different backend with `VITE_API_BASE_URL` (build time) or `?api=http://host:8000` (runtime, handy for a deployed GitHub Pages build).

Optional local scan target (no third-party site required):
```bash
docker compose --profile demo-target up demo-target   # OWASP Juice Shop on :3000
```

## Project Structure

```text
AI-Automated-Penetration-Testing/
|-- .github/
|   |-- ISSUE_TEMPLATE/
|   `-- workflows/       # CI/CD + GitHub Pages deploy
|-- docs/
|   |-- BACKLOG.md
|   |-- GITHUB_PROJECT_SETUP.md
|   |-- ROADMAP.md
|   |-- SPRINTS.md
|   `-- TEAM.md
|-- frontend/            # React + Tailwind multi-scanner dashboard
|-- src/
|   |-- backend/
|   |   |-- scanners/    # Nuclei/ZAP/Nikto wrappers (real binary + simulated fallback)
|   |   |-- correlation.py
|   |   |-- job_manager.py
|   |   |-- references.py
|   |   `-- schemas.py
|   |-- security_rag_engine/
|   `-- worker/
`-- tests/
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for branching, PR rules, and sprint board usage.

## License

Academic project. All rights reserved.
