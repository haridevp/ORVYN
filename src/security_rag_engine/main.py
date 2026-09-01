from fastapi import FastAPI, HTTPException, Depends
from typing import List, Dict, Optional
import requests
import asyncio
from sqlalchemy.orm import Session
from pydantic import BaseModel

from schemas import (
    ScannerFinding, TriageResult, HistoricalScanRequest,
    ScanRunRecord, ScanSummary, DeltaReport
)
from rag_pipeline import SecurityRAGPipeline
from historical_engine import ScanComparisonEngine
from knowledge_loader import seed_knowledge_base
from config import LM_STUDIO_URL

# Module 4 Extensions
from models_db import SessionLocal, init_db
from memory_service import MemoryService

app = FastAPI(title="Security RAG Engine", description="Cybersecurity RAG & AI Triage Engine", version="1.0.0")

# Initialize DB on startup
init_db()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

rag_pipeline = SecurityRAGPipeline()
comparison_engine = ScanComparisonEngine()

@app.get("/health")
def health_check():
    status = {"api": "ok", "lm_studio": "unknown"}
    try:
        response = requests.get(f"{LM_STUDIO_URL}/models", timeout=2)
        if response.status_code == 200:
            status["lm_studio"] = "ok"
        else:
            status["lm_studio"] = f"error: {response.status_code}"
    except Exception as e:
        status["lm_studio"] = f"unreachable: {str(e)}"
    return status

@app.post("/api/v1/kb/seed")
def seed_kb():
    try:
        count = seed_knowledge_base()
        return {"status": "success", "seeded_records": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/triage/single", response_model=TriageResult)
def triage_single(finding: ScannerFinding):
    try:
        return rag_pipeline.triage_finding(finding)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/triage/batch", response_model=List[TriageResult])
async def triage_batch(findings: List[ScannerFinding]):
    results = []
    for finding in findings:
        result = await asyncio.to_thread(rag_pipeline.triage_finding, finding)
        results.append(result)
    return results

@app.post("/api/v1/history/diff_legacy")
def history_diff_legacy(request: HistoricalScanRequest):
    # Old legacy mock endpoint from Module 3
    previous_findings: List[ScannerFinding] = []
    delta = comparison_engine.compare_scans(previous_findings, request.findings)
    return {
        "scan_id": request.scan_id,
        "delta": delta
    }

# ---- Module 4 New Endpoints ----

@app.post("/api/v1/history/record")
def record_scan_history(record: ScanRunRecord, db: Session = Depends(get_db)):
    ms = MemoryService(db)
    scan_run = ms.record_scan(record)
    return {"status": "success", "scan_id": scan_run.scan_id}

@app.get("/api/v1/history/timeline/{target_name}", response_model=List[ScanSummary])
def get_timeline(target_name: str, db: Session = Depends(get_db)):
    ms = MemoryService(db)
    return ms.get_timeline(target_name)

class DiffRequest(BaseModel):
    prev_scan_id: Optional[str] = None
    current_scan_id: Optional[str] = None
    target: Optional[str] = None

@app.post("/api/v1/history/diff", response_model=DeltaReport)
def diff_scans(req: DiffRequest, db: Session = Depends(get_db)):
    ms = MemoryService(db)
    if req.prev_scan_id and req.current_scan_id:
        try:
            return ms.compare_scans(req.prev_scan_id, req.current_scan_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
    elif req.target:
        try:
            return ms.diff_last_two_scans(req.target)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    else:
        raise HTTPException(status_code=400, detail="Must provide either (prev_scan_id & current_scan_id) or target")
