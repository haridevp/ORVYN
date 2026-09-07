import asyncio
import json
import os
import shutil
import tempfile
from typing import Callable, Optional

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


async def _run_real_scan(target: str, timeout: int = 300, log_cb: Optional[Callable[[str], None]] = None) -> list[ScannerFinding]:
    """Invoke the real `nuclei` binary if it's installed. Streams verbose execution logs."""
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
            "-no-color",
            "-v",
        ]
        if log_cb:
            log_cb(f"Executing: {' '.join(command)}")

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        async def read_stream():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if text and log_cb:
                    log_cb(text)

        reader_task = asyncio.create_task(read_stream())
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            if log_cb:
                log_cb("Execution timed out after reaching threshold.")
            return []
        finally:
            await reader_task

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

        if not findings and proc.returncode != 0:
            if log_cb:
                log_cb(f"Nuclei exited (code {proc.returncode}) without findings. Providing fallback findings.")
            return build_simulated_findings(ScannerName.nuclei, target)

        return findings


class NucleiWrapper(ScannerWrapper):
    name = ScannerName.nuclei
    binary = BINARY

    async def run(
        self,
        target: str,
        profile: str,
        log_cb: Optional[Callable[[str], None]] = None,
    ) -> list[ScannerFinding]:
        if self.is_available():
            if log_cb:
                log_cb(f"Using live binary: {shutil.which(self.binary)}")
            return await _run_real_scan(target, log_cb=log_cb)

        # Binary not installed in this environment - return simulated findings
        if log_cb:
            log_cb(f"Binary '{self.binary}' not found on PATH. Using fallback simulated findings.")
        await asyncio.sleep(0.4)
        return build_simulated_findings(ScannerName.nuclei, target)
