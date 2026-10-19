from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "backend"))

from schemas import ScannerFinding, ScannerName
from job_manager import identify_secondary_tools_from_findings


def test_secondary_tool_identification_sqli():
    findings = [
        ScannerFinding(
            id="f-sqli",
            tool=ScannerName.zap,
            target="https://target.com/search?q=test",
            vulnerability="SQL Injection - boolean based",
            severity="high",
            description="Parameter q appears to be vulnerable to SQL injection",
        )
    ]
    candidates = identify_secondary_tools_from_findings(findings, target="https://target.com")
    tools = [tool for tool, _reason in candidates]
    assert ScannerName.sqlmap in tools


def test_secondary_tool_identification_hidden_paths():
    findings = [
        ScannerFinding(
            id="f-dir",
            tool=ScannerName.nikto,
            target="https://target.com/backup/",
            vulnerability="Directory Indexing / 403 forbidden path",
            severity="medium",
            description="Hidden path /backup/ found on server",
        )
    ]
    candidates = identify_secondary_tools_from_findings(findings, target="https://target.com")
    tools = [tool for tool, _reason in candidates]
    assert ScannerName.ffuf in tools


def test_secondary_tool_identification_ssl():
    findings = [
        ScannerFinding(
            id="f-tls",
            tool=ScannerName.nuclei,
            target="https://target.com:443",
            vulnerability="Deprecated TLS 1.0 supported",
            severity="medium",
            description="Server accepts TLS 1.0 handshakes",
        )
    ]
    candidates = identify_secondary_tools_from_findings(findings, target="https://target.com:443")
    tools = [tool for tool, _reason in candidates]
    assert ScannerName.sslyze in tools
