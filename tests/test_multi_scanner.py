import time
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "backend"))

# See tests/test_basic.py for why this cache eviction is necessary: backend
# and security_rag_engine both use bare intra-package imports (e.g. `import
# schemas`) and share sys.path in the same pytest session.
for _name in ("schemas", "references", "correlation", "job_manager", "scanners"):
    sys.modules.pop(_name, None)

from fastapi.testclient import TestClient

from src.backend.main import app

import pytest
from job_manager import ScannerFinding, ScannerName, Severity, REGISTRY

# Using the client as a context manager keeps a single event loop alive for
# the whole test session, so the fire-and-forget asyncio background tasks
# started by /scan/start actually get to run to completion between polls.
client = TestClient(app).__enter__()


@pytest.fixture(autouse=True)
def mock_scanners_for_demo_targets(monkeypatch):
    """Test fixture isolating unit test demo targets from external binary dependencies."""
    from job_manager import REGISTRY as JM_REGISTRY

    async def mock_run(self, target, profile="web", in_scope=None, out_of_scope=None, log_cb=None, finding_cb=None, **kwargs):
        findings = []
        if self.name in (ScannerName.nuclei, ScannerName.zap, ScannerName.nikto):
            f1 = ScannerFinding(
                tool=self.name,
                target=target,
                vulnerability="Missing Security Headers",
                severity=Severity.low,
                description="Strict-Transport-Security header missing on host.",
                evidence=target,
                reference="CWE-693 / OWASP A05:2021",
            )
            findings.append(f1)
            if finding_cb:
                finding_cb(f1)

        if self.name == ScannerName.nuclei:
            f2 = ScannerFinding(
                tool=self.name,
                target=target,
                vulnerability="SQL Injection",
                severity=Severity.high,
                description="SQL injection in id param.",
                evidence=f"{target}/?id=1'",
                reference="https://cwe.mitre.org/data/definitions/89.html (CWE-89)",
            )
            findings.append(f2)
            if finding_cb:
                finding_cb(f2)
        elif self.name == ScannerName.zap:
            f2 = ScannerFinding(
                tool=self.name,
                target=target,
                vulnerability="SQL Injection",
                severity=Severity.medium,
                description="SQL injection heuristic alert.",
                evidence=f"{target}/?id=1'",
                reference="https://cwe.mitre.org/data/definitions/89.html (CWE-89)",
            )
            findings.append(f2)
            if finding_cb:
                finding_cb(f2)

        return findings

    for wrapper in JM_REGISTRY.values():
        monkeypatch.setattr(wrapper.__class__, "run", mock_run)
        monkeypatch.setattr(wrapper.__class__, "is_available", lambda self: True)



def _start_and_wait(target: str, scanners: list[str], timeout: float = 5.0) -> dict:
    response = client.post("/scan/start", json={"target": target, "scanners": scanners})
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]

    deadline = time.time() + timeout
    status_payload = response.json()
    while time.time() < deadline:
        status_payload = client.get(f"/scan/status/{scan_id}").json()
        if status_payload["overall_status"] == "completed":
            break
        time.sleep(0.05)
    assert status_payload["overall_status"] == "completed", status_payload
    return status_payload


def test_scan_start_requires_at_least_one_scanner():
    response = client.post("/scan/start", json={"target": "scanme.nmap.org", "scanners": []})
    assert response.status_code == 400


def test_scan_start_rejects_missing_target():
    response = client.post("/scan/start", json={"target": "ab"})
    assert response.status_code == 422


def test_unknown_scan_id_returns_404():
    assert client.get("/scan/status/does-not-exist").status_code == 404
    assert client.get("/scan/results/does-not-exist").status_code == 404
    assert client.get("/scan/does-not-exist").status_code == 404


def test_single_scanner_job_completes_with_per_scanner_status():
    status = _start_and_wait("single-scanner-demo.local", ["nuclei"])
    assert len(status["scanners"]) == 1
    scanner = status["scanners"][0]
    assert scanner["tool"] == "nuclei"
    assert scanner["status"] == "completed"
    assert scanner["findings_count"] > 0


def test_multi_scanner_job_runs_all_selected_tools_concurrently():
    status = _start_and_wait("demo-target.local", ["nuclei", "zap", "nikto"])
    tools = {s["tool"] for s in status["scanners"]}
    assert tools == {"nuclei", "zap", "nikto"}
    assert all(s["status"] == "completed" for s in status["scanners"])


def test_results_include_raw_and_correlated_findings():
    target = "correlation-demo.local"
    status = _start_and_wait(target, ["nuclei", "zap", "nikto"])
    results = client.get(f"/scan/results/{status['scan_id']}").json()

    assert results["target"] == target
    assert len(results["raw_findings"]) > 0
    assert all(f["target"] == target for f in results["raw_findings"])

    # correlated findings must reference real raw finding ids
    raw_ids = {f["id"] for f in results["raw_findings"]}
    for corr in results["correlated_findings"]:
        assert set(corr["source_finding_ids"]).issubset(raw_ids)
        assert corr["confidence"] >= 0 and corr["confidence"] <= 100


def test_correlation_engine_merges_cross_tool_duplicates_and_flags_conflicts():
    # Test fixtures intentionally report "Missing Security Headers" from all
    # three tools, and "SQL Injection" from nuclei+zap with different severities.
    target = "conflict-demo.local"
    status = _start_and_wait(target, ["nuclei", "zap", "nikto"])
    results = client.get(f"/scan/results/{status['scan_id']}").json()

    by_vuln = {c["vulnerability"]: c for c in results["correlated_findings"]}

    headers_finding = by_vuln["Missing Security Headers"]
    assert set(headers_finding["contributing_tools"]) == {"nuclei", "zap", "nikto"}
    assert headers_finding["confidence"] > 90

    sqli_finding = by_vuln["SQL Injection"]
    assert set(sqli_finding["contributing_tools"]) == {"nuclei", "zap"}
    assert sqli_finding["conflicting_severity"] is True
    assert sqli_finding["severity"] == "high"  # highest of the two reported severities

    assert results["duplicate_groups"] >= 2


def test_severity_distribution_counts_match_raw_findings():
    target = "severity-count-demo.local"
    status = _start_and_wait(target, ["nuclei"])
    results = client.get(f"/scan/results/{status['scan_id']}").json()

    dist = results["severity_distribution"]
    total = sum(dist.values())
    assert total == len(results["raw_findings"])


def test_findings_are_enriched_with_cwe_owasp_references():
    target = "reference-demo.local"
    status = _start_and_wait(target, ["nuclei", "zap"])
    results = client.get(f"/scan/results/{status['scan_id']}").json()

    sqli_findings = [f for f in results["raw_findings"] if f["vulnerability"] == "SQL Injection"]
    assert sqli_findings
    assert all(f["reference"] and "CWE-89" in f["reference"] for f in sqli_findings)


def test_target_probe_detects_unreachable_hosts():
    # Tests that non-existent host like scanme.sh is cleanly flagged with helpful message
    response = client.post("/target/probe", json={"target": "nonexistent-domain-12345.sh"})
    assert response.status_code == 200
    data = response.json()
    assert data["is_alive"] is False
    assert "DNS resolution failed" in data["error"]


def test_status_response_includes_progress_eta_and_live_findings():
    status = _start_and_wait("progress-eta-demo.local", ["nuclei"])
    assert "progress_pct" in status
    assert status["progress_pct"] == 100
    assert "eta_seconds" in status
    assert status["eta_seconds"] == 0
    assert "elapsed_seconds" in status
    assert status["elapsed_seconds"] >= 0
    assert "live_findings" in status
    assert len(status["live_findings"]) > 0
    assert "severity_distribution" in status

