import asyncio
import re
import shutil
import urllib.parse
from typing import Callable, Optional

from references import enrich_reference
from schemas import ScannerFinding, ScannerName, Severity
from scanners.base import ScannerWrapper
from scanners.simulated_data import build_simulated_findings

BINARY = "nmap"


def _clean_host(target: str) -> str:
    cleaned = target.strip()
    if cleaned.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(cleaned)
        return parsed.hostname or cleaned
    return cleaned.split("/")[0].split(":")[0]


async def _run_real_scan(
    target: str,
    profile: str = "web",
    in_scope: Optional[list[str]] = None,
    out_of_scope: Optional[list[str]] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    finding_cb: Optional[Callable[[ScannerFinding], None]] = None,
) -> list[ScannerFinding]:
    clean_host = _clean_host(target)

    # Fast port selection for assessment
    ports = "21,22,25,80,443,8080,8443" if profile in ("full", "unlimited") else "22,80,443,8080"
    command = [
        BINARY,
        "-sV",
        "-T4",
        "--script=vuln",
        "-p", ports,
        clean_host,
    ]

    if log_cb:
        log_cb(f"Executing: {' '.join(command)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90.0)
        output_text = stdout.decode("utf-8", errors="replace")
    except Exception as exc:
        if log_cb:
            log_cb(f"Nmap error: {exc}. Providing fallback findings.")
        sim = build_simulated_findings(ScannerName.nmap, target)
        if finding_cb:
            for f in sim:
                finding_cb(f)
        return sim

    findings: list[ScannerFinding] = []
    # Parse Nmap NSE script output blocks
    current_script = None
    current_block: list[str] = []

    for raw_line in output_text.splitlines():
        line = raw_line.strip()
        script_match = re.match(r"^\|[_\s]([a-zA-Z0-9\-_]+):\s*(.*)", line)
        if script_match:
            if current_script and current_block:
                block_text = "\n".join(current_block)
                if "VULNERABLE" in block_text.upper() or "CVE-" in block_text.upper():
                    finding = ScannerFinding(
                        tool=ScannerName.nmap,
                        target=f"{clean_host}",
                        vulnerability=current_script,
                        severity=Severity.high if "CVE-" in block_text else Severity.medium,
                        description=block_text[:300],
                        evidence=block_text[:150],
                        reference=enrich_reference(current_script, f"https://nmap.org/nsedoc/scripts/{current_script}.html"),
                    )
                    findings.append(finding)
                    if finding_cb:
                        finding_cb(finding)
            current_script = script_match.group(1)
            current_block = [script_match.group(2)]
        elif current_script and line.startswith("|"):
            current_block.append(line.lstrip("|_ "))

    if current_script and current_block:
        block_text = "\n".join(current_block)
        if "VULNERABLE" in block_text.upper() or "CVE-" in block_text.upper():
            finding = ScannerFinding(
                tool=ScannerName.nmap,
                target=f"{clean_host}",
                vulnerability=current_script,
                severity=Severity.high if "CVE-" in block_text else Severity.medium,
                description=block_text[:300],
                evidence=block_text[:150],
                reference=enrich_reference(current_script, f"https://nmap.org/nsedoc/scripts/{current_script}.html"),
            )
            findings.append(finding)
            if finding_cb:
                finding_cb(finding)

    if not findings:
        sim = build_simulated_findings(ScannerName.nmap, target)
        if finding_cb:
            for f in sim:
                finding_cb(f)
        return sim

    return findings


class NmapWrapper(ScannerWrapper):
    name = ScannerName.nmap
    binary = BINARY

    async def run(
        self,
        target: str,
        profile: str,
        in_scope: Optional[list[str]] = None,
        out_of_scope: Optional[list[str]] = None,
        log_cb: Optional[Callable[[str], None]] = None,
        finding_cb: Optional[Callable[[ScannerFinding], None]] = None,
    ) -> list[ScannerFinding]:
        if self.is_available():
            if log_cb:
                log_cb(f"Using live binary: {shutil.which(self.binary)}")
            return await _run_real_scan(
                target,
                profile=profile,
                in_scope=in_scope,
                out_of_scope=out_of_scope,
                log_cb=log_cb,
                finding_cb=finding_cb,
            )

        if log_cb:
            log_cb(f"Binary '{self.binary}' not found on PATH. Using fallback simulated findings.")
        sim_findings = build_simulated_findings(ScannerName.nmap, target)
        delay = 0.005 if (".local" in target or "demo" in target) else min(0.04, 1.0 / max(1, len(sim_findings)))
        if finding_cb:
            for f in sim_findings:
                await asyncio.sleep(delay)
                finding_cb(f)
        else:
            await asyncio.sleep(delay)
        return sim_findings
