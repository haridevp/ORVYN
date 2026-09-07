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


async def _run_real_scan(
    target: str,
    profile: str = "web",
    timeout: Optional[int] = None,
    in_scope: Optional[list[str]] = None,
    out_of_scope: Optional[list[str]] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    finding_cb: Optional[Callable[[ScannerFinding], None]] = None,
) -> list[ScannerFinding]:
    """Invoke the real `nuclei` binary if it's installed. Streams verbose execution logs."""
    # Profile-tuned configuration
    if profile == "recon":
        scan_timeout = timeout or 35
        tags = "cve,exposure,tech,misconfig,dns,ssl"
        extra_args = ["-tags", tags, "-timeout", "3", "-rate-limit", "150", "-concurrency", "25"]
    elif profile == "full":
        scan_timeout = timeout or 120
        extra_args = ["-severity", "info,low,medium,high,critical", "-timeout", "5", "-rate-limit", "150", "-concurrency", "30"]
    elif profile == "unlimited":
        # Unlimited mode: no artificial timeout threshold
        scan_timeout = timeout  # None -> runs until completion
        extra_args = ["-severity", "info,low,medium,high,critical", "-timeout", "8", "-rate-limit", "150", "-concurrency", "30"]
    else:  # "web" (default)
        scan_timeout = timeout or 60
        tags = "cve,xss,sqli,exposure,misconfig,auth,ssl,generic"
        extra_args = ["-tags", tags, "-timeout", "4", "-rate-limit", "150", "-concurrency", "25"]

    # Exclude out-of-scope hosts
    if out_of_scope:
        exclude_hosts = [r.strip().lstrip("*.") for r in out_of_scope if "/" not in r and r.strip()]
        if exclude_hosts:
            extra_args.extend(["-exclude-hosts", ",".join(exclude_hosts)])

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_file = os.path.join(tmp_dir, "nuclei_output.json")
        command = [
            BINARY,
            "-u", target,
            "-duc",  # disable update check to prevent waiting on github api
            "-json-export", output_file,
            "-no-color",
            "-v",
            *extra_args,
        ]
        timeout_label = f"{scan_timeout}s" if scan_timeout is not None else "UNLIMITED (no timeout)"
        if log_cb:
            log_cb(f"Executing: {' '.join(command)} (timeout: {timeout_label}, profile: {profile})")

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as exc:
            if log_cb:
                log_cb(f"Failed to spawn Nuclei process: {exc}. Providing fallback findings.")
            sim = build_simulated_findings(ScannerName.nuclei, target)
            if finding_cb:
                for f in sim:
                    finding_cb(f)
            return sim

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
            if scan_timeout is not None:
                await asyncio.wait_for(proc.wait(), timeout=scan_timeout)
            else:
                await proc.wait()
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            if log_cb:
                log_cb(f"Nuclei execution reached profile timeout ({scan_timeout}s). Wrapping up available findings.")
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
                                if finding_cb:
                                    finding_cb(finding)

        if not findings and proc.returncode != 0:
            if log_cb:
                log_cb(f"Nuclei exited (code {proc.returncode}) without findings. Providing fallback findings.")
            sim = build_simulated_findings(ScannerName.nuclei, target)
            if finding_cb:
                for f in sim:
                    finding_cb(f)
            return sim

        return findings


class NucleiWrapper(ScannerWrapper):
    name = ScannerName.nuclei
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

        # Binary not installed in this environment - return simulated findings staggered live
        if log_cb:
            log_cb(f"Binary '{self.binary}' not found on PATH. Using fallback simulated findings.")
        sim_findings = build_simulated_findings(ScannerName.nuclei, target)
        if finding_cb:
            for f in sim_findings:
                await asyncio.sleep(0.35)
                finding_cb(f)
        else:
            await asyncio.sleep(0.4)
        return sim_findings

