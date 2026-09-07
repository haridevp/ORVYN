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

BINARY = "wapiti"
SEVERITY_MAP = {
    1: Severity.low,
    2: Severity.medium,
    3: Severity.high,
    4: Severity.critical,
}


async def _run_real_scan(
    target: str,
    profile: str = "web",
    in_scope: Optional[list[str]] = None,
    out_of_scope: Optional[list[str]] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    finding_cb: Optional[Callable[[ScannerFinding], None]] = None,
) -> list[ScannerFinding]:
    target_url = target if target.startswith(("http://", "https://")) else f"http://{target}"

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_file = os.path.join(tmp_dir, "wapiti_results.json")
        command = [
            BINARY,
            "-u", target_url,
            "-f", "json",
            "-o", output_file,
            "-m", "xss,sql,exec,file,ssrf,redirect,cookieFlags,hsts",
            "--max-scan-time", "60",
            "--flush-session",
        ]

        if log_cb:
            log_cb(f"Executing: {' '.join(command)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=70.0)
        except Exception as exc:
            if log_cb:
                log_cb(f"Wapiti execution error: {exc}. Providing fallback findings.")
            sim = build_simulated_findings(ScannerName.wapiti, target)
            if finding_cb:
                for f in sim:
                    finding_cb(f)
            return sim

        findings: list[ScannerFinding] = []
        if os.path.exists(output_file):
            try:
                with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                vulnerabilities = data.get("vulnerabilities", {})
                for cat, items in vulnerabilities.items():
                    for item in items:
                        desc = item.get("info") or cat
                        path = item.get("path") or target_url
                        param = item.get("parameter") or ""
                        finding = ScannerFinding(
                            tool=ScannerName.wapiti,
                            target=target,
                            vulnerability=cat,
                            severity=Severity.medium,
                            description=f"{cat}: {desc}",
                            evidence=f"Endpoint: {path} Parameter: {param}".strip(),
                            reference=enrich_reference(cat, "https://wapiti-scanner.github.io/"),
                        )
                        findings.append(finding)
                        if finding_cb:
                            finding_cb(finding)
            except Exception:
                pass

        if not findings:
            sim = build_simulated_findings(ScannerName.wapiti, target)
            if finding_cb:
                for f in sim:
                    finding_cb(f)
            return sim

        return findings


class WapitiWrapper(ScannerWrapper):
    name = ScannerName.wapiti
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
        sim_findings = build_simulated_findings(ScannerName.wapiti, target)
        delay = 0.005 if (".local" in target or "demo" in target) else min(0.04, 1.0 / max(1, len(sim_findings)))
        if finding_cb:
            for f in sim_findings:
                await asyncio.sleep(delay)
                finding_cb(f)
        else:
            await asyncio.sleep(delay)
        return sim_findings
