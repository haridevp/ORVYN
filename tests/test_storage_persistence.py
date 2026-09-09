import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent / "src" / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from main import app
from storage import ScanStorage
from schemas import (
    ScanStartRequest,
    ScannerName,
    ScannerFinding,
    Severity,
    ScannerProgress,
    ScannerRunState,
)
from job_manager import ScanJob, job_manager
from templates.registry import template_registry

client = TestClient(app)


def test_storage_engine_crud(tmp_path):
    db_file = tmp_path / "test_orvyn.db"
    store = ScanStorage(db_path=str(db_file))

    req = ScanStartRequest(
        target="example.com",
        profile="web",
        scanners=[ScannerName.whatweb, ScannerName.nuclei],
        template="web_owasp_deep_audit",
    )
    job = ScanJob("scan-test-persist-1", req)
    job.template_name = "OWASP Top 10 Exhaustive Web Audit"
    job.add_log("system", "Scan started on example.com")
    job.findings.append(
        ScannerFinding(
            tool=ScannerName.nuclei,
            target="example.com",
            vulnerability="Exposed Git Config",
            severity=Severity.high,
            confidence=90,
            description="Git configuration file exposed",
            evidence="http://example.com/.git/config",
        )
    )

    store.save_job(job)

    # Fetch from store
    fetched = store.get_scan("scan-test-persist-1")
    assert fetched is not None
    assert fetched["scan_id"] == "scan-test-persist-1"
    assert fetched["target"] == "example.com"
    assert fetched["findings_count"] == 1
    assert len(fetched["findings"]) == 1
    assert fetched["findings"][0]["vulnerability"] == "Exposed Git Config"
    assert fetched["findings"][0]["severity"] == "high"
    assert len(fetched["logs"]) >= 1

    # List scans
    scans_list = store.list_scans()
    assert len(scans_list) >= 1
    assert any(s["scan_id"] == "scan-test-persist-1" for s in scans_list)

    # Delete scan
    deleted = store.delete_scan("scan-test-persist-1")
    assert deleted is True
    assert store.get_scan("scan-test-persist-1") is None


def test_job_manager_sqlite_reconstitution(tmp_path):
    req = ScanStartRequest(
        target="test-reconstitute.org",
        profile="recon",
        scanners=[ScannerName.nmap, ScannerName.sslyze],
    )
    job = ScanJob("scan-reconst-42", req)
    job.add_log("nmap", "Port 443 open")
    job.scanner_progress[ScannerName.nmap].status = ScannerRunState.completed
    job.findings.append(
        ScannerFinding(
            tool=ScannerName.nmap,
            target="test-reconstitute.org:443",
            vulnerability="Self-Signed SSL Certificate",
            severity=Severity.low,
            confidence=80,
            description="Certificate untrusted",
        )
    )

    # Save to global storage
    from storage import scan_storage
    scan_storage.save_job(job)

    # Purge in-memory dictionary
    if "scan-reconst-42" in job_manager._jobs:
        del job_manager._jobs["scan-reconst-42"]

    # Retrieve through job_manager - should reconstitute from SQLite
    reconstituted = job_manager.get("scan-reconst-42")
    assert reconstituted is not None
    assert reconstituted.scan_id == "scan-reconst-42"
    assert reconstituted.target == "test-reconstitute.org"
    assert len(reconstituted.findings) == 1
    assert reconstituted.findings[0].vulnerability == "Self-Signed SSL Certificate"
    assert len(reconstituted.logs) >= 1

    # Cleanup
    job_manager.delete_scan("scan-reconst-42")


def test_api_scans_history_and_deletion():
    # Start a scan via API
    resp = client.post(
        "/scan/start",
        json={
            "target": "history-test.com",
            "profile": "recon",
            "scanners": ["whatweb"],
            "template": "auto",
        },
    )
    assert resp.status_code == 202
    scan_data = resp.json()
    sid = scan_data["scan_id"]

    # Verify /scans endpoint returns the scan
    history_resp = client.get("/scans")
    assert history_resp.status_code == 200
    all_scans = history_resp.json()
    assert isinstance(all_scans, list)
    assert any(s["scan_id"] == sid for s in all_scans)

    # Verify /scan/history alias
    alias_resp = client.get("/scan/history")
    assert alias_resp.status_code == 200

    # Delete scan via API
    del_resp = client.delete(f"/scan/{sid}")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "deleted"


def test_all_30_templates_have_5_to_9_distinct_tools():
    templates = template_registry.list_templates()
    assert len(templates) == 30, f"Expected 30 templates, got {len(templates)}"

    for tmpl in templates:
        assert len(tmpl.scanners) >= 5, (
            f"Template '{tmpl.id}' has only {len(tmpl.scanners)} tools: {tmpl.tools}. "
            "Expected at least 5 tools."
        )
        assert len(tmpl.scanners) <= 9
        assert len(tmpl.tool_chain) >= 5
        # Ensure no duplicates within a template's tool list
        tool_names = [s.value if hasattr(s, "value") else str(s) for s in tmpl.scanners]
        assert len(tool_names) == len(set(tool_names)), (
            f"Template '{tmpl.id}' contains duplicate tools: {tool_names}"
        )
