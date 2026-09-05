# Multi-Scanner Dashboard

React + TypeScript + Tailwind dashboard for the AI-Automated-Penetration-Testing backend (Module 2: multi-scanner integration & vulnerability correlation).

## Develop

```bash
npm install
npm run dev
```

Talks to `http://localhost:8000` by default. Override with:
- `VITE_API_BASE_URL` env var at build time (see `.env.example`)
- `?api=http://your-host:8000` query param at runtime

If no backend is reachable, the dashboard falls back to labeled demo data instead of a blank/broken page - useful when this is deployed standalone (e.g. GitHub Pages) without a hosted backend.

## Build

```bash
npm run build   # outputs to dist/, deployed by .github/workflows/pages.yml
```

`vite.config.ts` sets `base: '/'`, which assumes a custom domain attached to GitHub Pages (serves from the domain root). If you instead deploy to the default `<org>.github.io/AI-Automated-Penetration-Testing/` URL, change `base` to `'/AI-Automated-Penetration-Testing/'`.

## Why the backend isn't also on GitHub Pages

The backend needs Celery/Redis/Postgres and (optionally) real scanner binaries - none of which run on static hosting. Run it via `docker compose up` (see repo root `README.md`) on any host you control, then point the deployed dashboard at it.
