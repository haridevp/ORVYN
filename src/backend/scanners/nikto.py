import asyncio
import json
import os
import shutil
import tempfile

from references import enrich_reference
from schemas import ScannerFinding, ScannerName, Severity
from scanners.base import ScannerWrapper
from scanners.simulated_data import build_simulated_findings

BINARY = "nikto"


def _normalize_item(item: dict, target: str) -> ScannerFinding:
    name = item.get("msg") or "Unnamed Finding"
    return ScannerFinding(
        tool=ScannerName.nikto,
        target=target,
        vulnerability=name,
        severity=Severity.medium if item.get("OSVDB") else Severity.low,
        description=name,
        evidence=item.get("uri") or target,
        reference=enrich_reference(name, f"OSVDB-{item['OSVDB']}" if item.get("OSVDB") else None),
    )


async def _run_real_scan(target: str, timeout: int = 300) -> list[ScannerFinding]:
    """Invoke the real `nikto` binary if installed. Only ever run this
    against systems you are authorized to test."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_file = os.path.join(tmp_dir, "nikto_output.json")
        command = ["-h", target, "-Format", "json", "-output", output_file]
        proc = await asyncio.create_subprocess_exec(
            BINARY, *command,
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
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                try:
                    report = json.load(f)
                except json.JSONDecodeError:
                    return []
            vulnerabilities = report.get("vulnerabilities", []) if isinstance(report, dict) else []
            for item in vulnerabilities:
                findings.append(_normalize_item(item, target))
        return findings


class NiktoWrapper(ScannerWrapper):
    name = ScannerName.nikto

    async def run(self, target: str, profile: str) -> list[ScannerFinding]:
        if shutil.which(BINARY):
            return await _run_real_scan(target)
        await asyncio.sleep(0.3)
        return build_simulated_findings(ScannerName.nikto, target)
