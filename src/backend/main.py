from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(
    title="AI Automated Penetration Testing API",
    version="0.2.0",
    description="Architecture-proof API skeleton for the AI pentesting platform.",
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
        "layers": ["FastAPI API", "Celery worker", "Redis broker", "PostgreSQL storage"],
        "implemented_endpoints": [
            "GET /",
            "GET /health",
            "GET /architecture/proof",
            "POST /scans",
            "GET /scans/{scan_id}",
            "GET /reports/{scan_id}",
        ],
        "planned_integrations": ["Nmap", "OWASP ZAP", "Nuclei", "RAG validator"],
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
