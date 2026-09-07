import asyncio
import json
import os
import shutil
import tempfile

from references import enrich_reference
from schemas import ScannerFinding, ScannerName, Severity
from scanners.base import ScannerWrapper
from scanners.simulated_data import build_simulated_findings

BINARY = "zap-baseline.py"
RISK_MAP = {
    "3": Severity.high,
    "2": Severity.medium,
    "1": Severity.low,
    "0": Severity.info,
}


def _normalize_alert(alert: dict, target: str) -> ScannerFinding:
    name = alert.get("alert") or alert.get("name") or "Unnamed Finding"
    instances = alert.get("instances") or []
    evidence = None
    if instances and isinstance(instances, list):
        evidence = instances[0].get("uri") or instances[0].get("evidence")
    return ScannerFinding(
        tool=ScannerName.zap,
        target=target,
        vulnerability=name,
        severity=RISK_MAP.get(str(alert.get("riskcode", "0")), Severity.info),
        description=alert.get("desc") or alert.get("description") or "No detailed description provided.",
        evidence=evidence or target,
        reference=enrich_reference(name, alert.get("reference")),
    )


async def _run_real_scan(target: str, timeout: int = 600) -> list[ScannerFinding]:
    """Invoke the real ZAP baseline scan if installed. Only ever run this
    against systems you are authorized to test."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        report_path = os.path.join(tmp_dir, "zap_report.json")
        command = [BINARY, "-t", target, "-J", report_path, "-m", "5"]
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return []

        findings: list[ScannerFinding] = []
        if os.path.exists(report_path):
            with open(report_path, "r") as f:
                try:
                    report = json.load(f)
                except json.JSONDecodeError:
                    return []
            for site in report.get("site", []):
                for alert in site.get("alerts", []):
                    findings.append(_normalize_alert(alert, target))
        return findings


class ZapWrapper(ScannerWrapper):
    name = ScannerName.zap

    async def run(self, target: str, profile: str) -> list[ScannerFinding]:
        if shutil.which(BINARY):
            return await _run_real_scan(target)
        await asyncio.sleep(0.6)
        return build_simulated_findings(ScannerName.zap, target)
