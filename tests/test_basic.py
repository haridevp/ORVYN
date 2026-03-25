from pathlib import Path
import sys


sys.path.append(str(Path(__file__).resolve().parents[1]))

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
