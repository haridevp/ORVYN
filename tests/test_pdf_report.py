from pathlib import Path
import sys
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "backend"))

from src.backend.pdf_report import generate_pentest_pdf
from src.backend.main import app
from fastapi.testclient import TestClient


def test_pdf_report_generation():
    data = {
        "target": "scanme.nmap.org",
        "profile": "web",
        "scan_id": "test-pdf-scan",
        "in_scope": ["*.scanme.nmap.org", "scanme.nmap.org"],
        "out_of_scope": ["admin.scanme.nmap.org"],
        "duplicate_groups": 2,
        "severity_distribution": {"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 1},
        "raw_findings": [{"id": "1"}, {"id": "2"}],
        "correlated_findings": [
            {
                "vulnerability": "Remote Code Execution via Apache Struts",
                "severity": "critical",
                "contributing_tools": ["nuclei", "zap"],
                "confidence": 95,
                "evidence": ["POST /test.action returned code execution payload match"],
                "remediation": "Upgrade Apache Struts library immediately.",
                "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638",
            }
        ],
    }

    pdf_bytes = generate_pentest_pdf(data)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes
    assert b"scanme.nmap.org" in pdf_bytes
    assert b"CRITICAL" in pdf_bytes


def test_pdf_report_endpoint():
    client = TestClient(app)
    # Start a scan
    start_resp = client.post(
        "/scan/start",
        json={"target": "scanme.nmap.org", "scanners": ["nuclei"], "profile": "recon"},
    )
    assert start_resp.status_code == 202
    scan_id = start_resp.json()["scan_id"]

    # Fetch PDF report
    pdf_resp = client.get(f"/scan/report/{scan_id}/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert "attachment; filename=pentest-report-" in pdf_resp.headers["content-disposition"]
    assert pdf_resp.content.startswith(b"%PDF-1.4")
