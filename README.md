# AI-Automated-Penetration-Testing

> Final Year Project | Semester 6-8 | Team of 4

An AI-assisted penetration testing platform that coordinates scan requests, asynchronous worker execution, and validation-ready reporting. The current repository contains the project foundation, delivery workflow, and API proof-of-architecture for the larger system planned in the review deck.

[Full Backlog](docs/BACKLOG.md) | [Sprint Plan](docs/SPRINTS.md) | [Roadmap](docs/ROADMAP.md) | [Team](docs/TEAM.md)

## Current Status

Implemented in this repository today:
- FastAPI backend skeleton with health, scan submission, scan lookup, report preview, and architecture-proof endpoints
- Celery worker skeleton for asynchronous scan execution
- Dockerfiles for backend and worker
- `docker-compose.yml` with backend, worker, Redis, and PostgreSQL services
- GitHub Actions workflow aligned to `develop` for CI and merge-to-`main` for deployment validation
- Agile planning artifacts: backlog, sprint board guidance, roadmap, team roles, and issue templates

Planned next layers:
- React/Tailwind dashboard
- Scanner integrations for Nmap, ZAP, and Nuclei
- PostgreSQL persistence and migrations
- RAG validation using LangChain, ChromaDB, and Ollama
- Authentication, role-based access, and report export

## Modules

| Module | Status | Notes |
|--------|--------|-------|
| Reconnaissance | Planned | Nmap/Nuclei integration tracked in backlog |
| Vulnerability Scanner | Planned | API and worker flow prepared for scanner orchestration |
| AI Validation | Planned | RAG validation stack documented, not implemented yet |
| Reporting | In Progress | Report preview endpoint and result schema stub added |
| Backend API | Implemented Foundation | FastAPI endpoints and request/response models present |
| Queue / Worker | Implemented Foundation | Celery task skeleton present |
| Dashboard / UI | Planned | React/Tailwind phase starts in later sprint |
| DevOps | Implemented Foundation | Docker Compose and GitHub Actions in repo |

## Tech Stack

Current repo:
- FastAPI for API routing
- Celery with Redis for asynchronous execution
- PostgreSQL container for persistence layer setup
- Docker Compose for local orchestration
- GitHub Actions for CI/CD

Planned integration stack:
- React and Tailwind CSS for dashboard UI
- LangChain, Ollama, and ChromaDB for validation and retrieval
- Nmap, OWASP ZAP, and Nuclei for scan evidence collection

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
- `POST /scans`
- `GET /scans/{scan_id}`
- `GET /reports/{scan_id}`

These endpoints provide the architecture proof expected in the panel review while deeper scanner, database, and RAG integrations are still under active development.

## Project Structure

```text
AI-Automated-Penetration-Testing/
|-- .github/
|   |-- ISSUE_TEMPLATE/
|   `-- workflows/
|-- docs/
|   |-- BACKLOG.md
|   |-- GITHUB_PROJECT_SETUP.md
|   |-- ROADMAP.md
|   |-- SPRINTS.md
|   `-- TEAM.md
|-- src/
|   |-- backend/
|   `-- worker/
`-- tests/
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for branching, PR rules, and sprint board usage.

## License

Academic project. All rights reserved.
