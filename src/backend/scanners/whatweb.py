import asyncio
import shutil
import urllib.parse
from typing import Callable, Optional

from references import enrich_reference
from schemas import ScannerFinding, ScannerName, Severity
from scanners.base import ScannerWrapper
from scanners.simulated_data import build_simulated_findings

BINARY = "whatweb"


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
    target_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    clean_host = _clean_host(target)

    command = [
        BINARY,
        "--color=never",
        "-a", "1",
        target_url,
    ]

    if log_cb:
        log_cb(f"Executing: {' '.join(command)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=35.0)
        output_text = stdout.decode("utf-8", errors="replace")
    except Exception as exc:
        if log_cb:
            log_cb(f"WhatWeb process error: {exc}. Providing fallback findings.")
        sim = build_simulated_findings(ScannerName.whatweb, target)
        if finding_cb:
            for f in sim:
                finding_cb(f)
        return sim

    findings: list[ScannerFinding] = []
    for line in output_text.splitlines():
        line = line.strip()
        if not line or "[200 OK]" in line and "Country[" in line and "IP[" in line:
            continue
        if any(keyword in line.lower() for keyword in ["country:", "ip:", "http status:"]):
            continue

        finding = ScannerFinding(
            tool=ScannerName.whatweb,
            target=target,
            vulnerability="Web Technology Stack Fingerprint",
            severity=Severity.info,
            description=line,
            evidence=f"Host: {clean_host} ({line[:120]})",
            reference=enrich_reference("Web Technology Stack Fingerprint", "https://github.com/urbanadventurer/WhatWeb"),
        )
        findings.append(finding)
        if finding_cb:
            finding_cb(finding)

    if not findings:
        sim = build_simulated_findings(ScannerName.whatweb, target)
        if finding_cb:
            for f in sim:
                finding_cb(f)
        return sim

    return findings


class WhatWebWrapper(ScannerWrapper):
    name = ScannerName.whatweb
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
        sim_findings = build_simulated_findings(ScannerName.whatweb, target)
        delay = 0.005 if (".local" in target or "demo" in target) else min(0.04, 1.0 / max(1, len(sim_findings)))
        if finding_cb:
            for f in sim_findings:
                await asyncio.sleep(delay)
                finding_cb(f)
        else:
            await asyncio.sleep(delay)
        return sim_findings
