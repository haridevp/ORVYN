import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[2]))
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "security_rag_engine"))

from src.security_rag_engine.models_db import Base
from src.security_rag_engine.memory_service import MemoryService, compute_fingerprint
from src.security_rag_engine.schemas import ScanRunRecord, ScannerFinding

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    yield db
    db.close()

def test_fingerprint_immutability():
    # Test 3: Verify fingerprint immutability against whitespace or ordering variations
    fp1 = compute_fingerprint("target.com", "Nuclei", "XSS", " <script>alert(1)</script> ")
    fp2 = compute_fingerprint("target.com", "Nuclei", "XSS", "<script>alert(1)</script>")
    assert fp1 == fp2

def test_memory_engine_flow(db_session):
    ms = MemoryService(db_session)
    
    # Test 1: Scan 1 with [XSS, SQLi]
    finding_xss = ScannerFinding(tool="ZAP", target="app", vulnerability="XSS", severity="High", description="...", evidence="<script>")
    finding_sqli = ScannerFinding(tool="Nuclei", target="app", vulnerability="SQLi", severity="Critical", description="...", evidence="' OR 1=1")
    
    scan1 = ScanRunRecord(
        scan_id="scan-1",
        target="app",
        scanner_tools_used="ZAP,Nuclei",
        findings=[finding_xss, finding_sqli]
    )
    
    run1 = ms.record_scan(scan1)
    assert len(run1.findings) == 2
    assert all(f.status == "New" for f in run1.findings)
    
    # Test 2: Scan 2 with [SQLi, SSRF] -> SQLi Persistent, XSS Resolved, SSRF New.
    finding_ssrf = ScannerFinding(tool="Nuclei", target="app", vulnerability="SSRF", severity="High", description="...", evidence="http://169.254.169.254")
    
    scan2 = ScanRunRecord(
        scan_id="scan-2",
        target="app",
        scanner_tools_used="Nuclei",
        findings=[finding_sqli, finding_ssrf]
    )
    
    run2 = ms.record_scan(scan2)
    # The scan run findings should include the resolved one
    assert len(run2.findings) == 3 # SQLi (Persistent), SSRF (New), XSS (Resolved)
    
    statuses = {f.vulnerability_title: f.status for f in run2.findings}
    assert statuses["SQLi"] == "Persistent"
    assert statuses["SSRF"] == "New"
    assert statuses["XSS"] == "Resolved"
    
    # Test diff
    diff = ms.compare_scans("scan-1", "scan-2")
    assert diff.summary["new"] == 1
    assert diff.summary["persistent"] == 1
    assert diff.summary["resolved"] == 1
