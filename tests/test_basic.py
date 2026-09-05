from pathlib import Path
import sys


sys.path.append(str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "backend"))

# src/backend and src/security_rag_engine both use bare intra-package imports
# (e.g. `import schemas`) so they can run flat inside their own Docker image.
# When both live on sys.path in the same pytest session, whichever test file
# imports first "wins" the bare name for the rest of the run. Evict any stale
# cached module so this file always gets *this* package's version.
for _name in ("schemas", "references", "correlation", "job_manager", "scanners"):
    sys.modules.pop(_name, None)

from src.backend.main import ScanRequest, architecture_proof, create_scan, get_scan, health


def test_health_endpoint():
    payload = health()
    assert payload["status"] == "ok"
    assert payload["services"]["api"] == "up"


def test_create_scan_and_lookup():
    created = create_scan(
        ScanRequest(target="scanme.nmap.org", profile="recon", requested_by="pytest")
    )
    assert created["status"] == "queued"
    assert created["queue_mode"] == "stub"

    looked_up = get_scan(created["scan_id"])
    assert looked_up["target"] == "scanme.nmap.org"


def test_architecture_proof_endpoint():
    payload = architecture_proof()
    assert "POST /scans" in payload["implemented_endpoints"]
