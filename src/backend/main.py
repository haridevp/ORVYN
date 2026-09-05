from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from job_manager import job_manager
from schemas import ScanResultsResponse, ScanStartRequest, ScanStatusResponse


app = FastAPI(
    title="AI Automated Penetration Testing API",
    version="0.3.0",
    description="Multi-scanner orchestration API for the AI pentesting platform.",
)

# Dashboard is a static SPA (GitHub Pages / local dev server) hosted on a
# different origin than this API, so it needs CORS to call /scan/* directly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


SCAN_STORE: dict[str, dict] = {}


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=3, description="Hostname, IP, or URL to assess")
    profile: Literal["recon", "web", "full"] = "recon"
    requested_by: str = Field(default="panel-review-demo")


class ScanStatus(BaseModel):
    scan_id: str
    task_id: str
    target: str
    profile: str
    status: Literal["queued", "running", "completed"]
    queue_mode: Literal["stub", "celery"]
    created_at: str


def _queue_scan(request: ScanRequest) -> tuple[str, str]:
    # This keeps the API demonstrable even when Redis/Celery is not running.
    return "stub", f"task-{uuid4()}"


@app.get("/")
def home():
    return {
        "message": "AI Pentest API running",
        "docs": "/docs",
        "version": app.version,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "services": {
            "api": "up",
            "queue": "configured",
            "database": "containerized",
        },
    }


@app.get("/architecture/proof")
def architecture_proof():
    return {
        "layers": [
            "FastAPI API",
            "Multi-scanner job manager (Nuclei/ZAP/Nikto)",
            "Result normalizer + correlation engine",
            "Celery worker",
            "Redis broker",
            "PostgreSQL storage",
        ],
        "implemented_endpoints": [
            "GET /",
            "GET /health",
            "GET /architecture/proof",
            "POST /scans",
            "GET /scans/{scan_id}",
            "GET /reports/{scan_id}",
            "POST /scan/start",
            "GET /scan/status/{scan_id}",
            "GET /scan/results/{scan_id}",
            "GET /scan/{scan_id}",
        ],
        "planned_integrations": ["OpenVAS", "RAG validator", "MCP tool layer"],
    }


@app.post("/scans", status_code=202, response_model=ScanStatus)
def create_scan(request: ScanRequest):
    queue_mode, task_id = _queue_scan(request)
    scan_id = f"scan-{uuid4()}"
    scan = {
        "scan_id": scan_id,
        "task_id": task_id,
        "target": request.target,
        "profile": request.profile,
        "status": "queued",
        "queue_mode": queue_mode,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "requested_by": request.requested_by,
    }
    SCAN_STORE[scan_id] = scan
    return scan


@app.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: str):
    scan = SCAN_STORE.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/reports/{scan_id}")
def get_report(scan_id: str):
    scan = SCAN_STORE.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "scan_id": scan_id,
        "summary": "Report preview generated from queued scan metadata.",
        "target": scan["target"],
        "validation_status": "pending-rag-validation",
    }


# ---------------------------------------------------------------------------
# Module 2 - Multi-Scanner Integration & Vulnerability Correlation
# ---------------------------------------------------------------------------
# These endpoints supersede the single-scanner /scans stub above: a scan job
# fans out to every selected scanner concurrently, tracks per-scanner status,
# and exposes both raw and correlated (de-duplicated) findings.


@app.post("/scan/start", status_code=202, response_model=ScanStatusResponse)
async def start_scan(request: ScanStartRequest):
    if not request.scanners:
        raise HTTPException(status_code=400, detail="At least one scanner must be selected")
    job = await job_manager.start_scan(request)
    return job.to_status_response()


@app.get("/scan/status/{scan_id}", response_model=ScanStatusResponse)
def get_scan_status(scan_id: str):
    job = job_manager.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return job.to_status_response()


@app.get("/scan/results/{scan_id}", response_model=ScanResultsResponse)
def get_scan_results(scan_id: str):
    job = job_manager.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return job.to_results_response()


@app.get("/scan/{scan_id}", response_model=ScanStatusResponse)
def get_scan_job(scan_id: str):
    job = job_manager.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return job.to_status_response()
