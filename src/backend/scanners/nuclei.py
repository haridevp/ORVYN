import asyncio
import json
import os
import shutil
import tempfile

from references import enrich_reference
from schemas import ScannerFinding, ScannerName, Severity
from scanners.base import ScannerWrapper
from scanners.simulated_data import build_simulated_findings

BINARY = "nuclei"
SEVERITY_MAP = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
    "unknown": Severity.info,
}


def _normalize_raw_line(raw: dict, target: str) -> ScannerFinding | None:
    info = raw.get("info") or {}
    if not isinstance(info, dict):
        info = {}
    name = info.get("name", "Unnamed Finding")
    severity = SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), Severity.info)
    return ScannerFinding(
        tool=ScannerName.nuclei,
        target=target,
        vulnerability=name,
        severity=severity,
        description=info.get("description") or "No detailed description provided.",
        evidence=raw.get("matched-at") or raw.get("host") or target,
        reference=enrich_reference(name, (info.get("reference") or [None])[0] if isinstance(info.get("reference"), list) else info.get("reference")),
    )


async def _run_real_scan(target: str, timeout: int = 300) -> list[ScannerFinding]:
    """Invoke the real `nuclei` binary if it's installed. Only ever run this
    against systems you are authorized to test."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_file = os.path.join(tmp_dir, "nuclei_output.json")
        command = [
            BINARY,
            "-u", target,
            "-severity", "info,low,medium,high,critical",
            "-json-export", output_file,
            "-rate-limit", "150",
            "-concurrency", "25",
            "-timeout", "5",
            "-silent",
        ]
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
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    items = parsed if isinstance(parsed, list) else [parsed]
                    for item in items:
                        if isinstance(item, dict):
                            finding = _normalize_raw_line(item, target)
                            if finding:
                                findings.append(finding)
        return findings


class NucleiWrapper(ScannerWrapper):
    name = ScannerName.nuclei

    async def run(self, target: str, profile: str) -> list[ScannerFinding]:
        if shutil.which(BINARY):
            return await _run_real_scan(target)
        # Binary not installed in this environment - return simulated findings
        # behind the same unified schema so the API/UI/correlation engine are
        # exercised end-to-end. Swap in a real `nuclei` install to go live.
        await asyncio.sleep(0.4)
        return build_simulated_findings(ScannerName.nuclei, target)
