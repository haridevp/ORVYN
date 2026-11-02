from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "backend"))

for _name in ("schemas", "references", "correlation", "job_manager", "scanners", "templates", "environment", "mcp"):
    sys.modules.pop(_name, None)

import pytest
from scanners.nmap import NmapWrapper
from scanners.cpe_knowledge import match_service_cves
from correlation import correlate_findings
from environment import detect_environment, ExecutionMode
from mcp.tools_catalog import HEXSTRIKE_TOOLS_CATALOG


def test_hexstrike_catalog_size_and_diversity():
    """Verify HexStrike MCP tools catalog contains 50 to 70+ curated tools across all security domains."""
    assert len(HEXSTRIKE_TOOLS_CATALOG) >= 50
    assert len(HEXSTRIKE_TOOLS_CATALOG) <= 80
    
    categories = {tool.category for tool in HEXSTRIKE_TOOLS_CATALOG}
    expected_categories = {
        "Reconnaissance & OSINT",
        "Content Discovery & Spidering",
        "Web Vulnerability Scanning",
        "Network, SSL/TLS & Infrastructure",
        "Directory & Parameter Fuzzing",
        "Injection & Exploitation Testing",
        "Cloud, Secrets & Configuration Audit",
        "Authentication & Credential Auditing",
    }
    assert expected_categories.issubset(categories)


def test_strict_docker_container_mode_enforced():
    """Verify that native execution is strictly restricted to Kali Linux and Parrot OS."""
    env = detect_environment()
    if env.is_kali:
        assert env.execution_mode == ExecutionMode.NATIVE_KALI
    elif env.is_parrot:
        assert env.execution_mode == ExecutionMode.NATIVE_PARROT
    else:
        # Non-Kali/Parrot host must always be DOCKERIZED_MCP
        assert env.execution_mode == ExecutionMode.DOCKERIZED_MCP


def test_nmap_vulners_parsing_returns_over_200_vulnerabilities():
    """Verify that parsing genuine Nmap Vulners output against scanme.nmap.org returns 200+ distinct vulnerabilities."""
    sample_log = Path("/home/haridev/.gemini/antigravity-ide/brain/5a81e517-e046-47c3-870c-0dd6d557f5d0/.system_generated/tasks/task-888.log")
    if not sample_log.exists():
        pytest.skip("Sample task-888.log not available in current environment")

    raw_output = sample_log.read_text()
    raw_findings = NmapWrapper.parse_output(raw_output, "scanme.nmap.org")
    assert len(raw_findings) >= 200, f"Expected 200+ raw findings, got {len(raw_findings)}"
    
    correlated = correlate_findings(raw_findings)
    assert len(correlated) >= 200, f"Expected 200+ correlated vulnerabilities, got {len(correlated)}"


def test_cpe_knowledge_base_covers_apache_openssh_and_os():
    """Verify deterministic CVE matching for banners discovered on scanme.nmap.org."""
    apache_cves = match_service_cves("Apache/2.4.7 (Ubuntu)")
    assert len(apache_cves) >= 25
    cve_ids = [c["cve"] for c in apache_cves]
    assert "CVE-2021-40438" in cve_ids
    assert "CVE-2019-0211" in cve_ids

    openssh_cves = match_service_cves("OpenSSH 6.6.1p1 Ubuntu")
    assert len(openssh_cves) >= 20
    ssh_ids = [c["cve"] for c in openssh_cves]
    assert "CVE-2024-6387" in ssh_ids
    assert "CVE-2023-38408" in ssh_ids
