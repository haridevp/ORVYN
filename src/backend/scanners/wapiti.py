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
        # Use exact Wapiti lowercase module names including http_headers and csp
        command = [
            BINARY,
            "-u", target_url,
            "-f", "json",
            "-o", output_file,
            "-m", "http_headers,csp,xss,sql,exec,file,ssrf,redirect,cookieflags",
            "--max-scan-time", "40",
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
            
            async def read_stream():
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    text = line.decode("utf-8", errors="replace").strip()
                    if text and log_cb:
                        if not text.startswith("█") and not text.startswith("Problem with local"):
                            log_cb(text)

            reader_task = asyncio.create_task(read_stream())
            try:
                await asyncio.wait_for(proc.wait(), timeout=50.0)
            except asyncio.TimeoutError:
                try:
                    proc.terminate()
                except Exception:
                    pass
                if log_cb:
                    log_cb("Wapiti scan reached max scan time. Collecting parsed results.")
            finally:
                if not reader_task.done():
                    try:
                        await asyncio.wait_for(reader_task, timeout=1.5)
                    except (asyncio.TimeoutError, asyncio.CancelledError):
                        reader_task.cancel()
        except Exception as exc:
            if log_cb:
                log_cb(f"Wapiti execution error: {exc}. Scan skipped.")
            return []

        findings: list[ScannerFinding] = []
        if os.path.exists(output_file):
            try:
                with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                vulnerabilities = data.get("vulnerabilities", {})
                seen_vulns = set()
                for cat, items in vulnerabilities.items():
                    for item in items:
                        info_msg = item.get("info") or cat
                        path = item.get("path") or target_url
                        param = item.get("parameter") or ""
                        level = item.get("level", 1)
                        sev = SEVERITY_MAP.get(level, Severity.medium)
                        
                        vuln_title = f"{cat}: {info_msg}" if info_msg != cat else cat
                        if vuln_title in seen_vulns:
                            continue
                        seen_vulns.add(vuln_title)

                        curl_cmd = item.get("curl_command") or ""
                        req_str = item.get("http_request") or ""
                        evidence_parts = [f"Path: {path}"]
                        if param:
                            evidence_parts.append(f"Param: {param}")
                        if curl_cmd:
                            evidence_parts.append(f"Reproduce: {curl_cmd}")
                        elif req_str:
                            evidence_parts.append(f"Request: {req_str.splitlines()[0]}")

                        finding = ScannerFinding(
                            tool=ScannerName.wapiti,
                            target=target,
                            vulnerability=vuln_title,
                            severity=sev,
                            description=f"Wapiti web application audit detected {vuln_title}. {info_msg}",
                            evidence=" | ".join(evidence_parts),
                            reference=enrich_reference(cat, "https://wapiti-scanner.github.io/"),
                        )
                        findings.append(finding)
                        if finding_cb:
                            finding_cb(finding)
                        if log_cb:
                            log_cb(f"🎯 Wapiti finding: [{finding.severity.upper()}] {finding.vulnerability}")
            except Exception as e:
                if log_cb:
                    log_cb(f"Wapiti report parsing note: {e}")

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
            log_cb(f"Binary '{self.binary}' not found on PATH. Real scan skipped.")
        return []
