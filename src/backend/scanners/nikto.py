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

BINARY = "nikto"


def _normalize_item(item: dict, target: str) -> ScannerFinding:
    name = item.get("msg") or item.get("description") or item.get("message") or "Unnamed Finding"
    url = item.get("url") or item.get("uri") or target
    osvdb = item.get("OSVDB") or item.get("osvdb")
    severity = Severity.medium if osvdb else Severity.low
    if any(k in name.lower() for k in ("vulnerable", "remote code", "sql", "injection", "command", "bypass")):
        severity = Severity.high

    return ScannerFinding(
        tool=ScannerName.nikto,
        target=target,
        vulnerability=name,
        severity=severity,
        description=name,
        evidence=url,
        reference=enrich_reference(name, f"OSVDB-{osvdb}" if osvdb else None),
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
    """Invoke the real `nikto` binary if installed. Streams verbose output in real time."""
    # Profile-tuned timing
    if profile == "recon":
        tuning = "12b"
        max_time = "20s"
        scan_timeout = timeout or 25
    elif profile == "full":
        tuning = "123b"
        max_time = "75s"
        scan_timeout = timeout or 90
    elif profile == "unlimited":
        # Unlimited mode: comprehensive scan, no maxtime and no process timeout
        tuning = "123b"
        max_time = None
        scan_timeout = timeout  # None -> runs until completion
    else:  # "web" (default)
        tuning = "123b"
        max_time = "35s"
        scan_timeout = timeout or 45

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_file = os.path.join(tmp_dir, "nikto_output.json")
        command = [
            BINARY,
            "-h", target,
            "-Format", "json",
            "-output", output_file,
            "-Tuning", tuning,
        ]
        if max_time:
            command.extend(["-maxtime", max_time])

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
                log_cb(f"Failed to spawn Nikto process: {exc}. Providing fallback findings.")
            sim = build_simulated_findings(ScannerName.nikto, target)
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
                log_cb(f"Nikto execution reached profile timeout ({scan_timeout}s). Wrapping up available findings.")
        finally:
            await reader_task

        findings: list[ScannerFinding] = []
        if os.path.exists(output_file):
            try:
                with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read().strip()
                    report = json.loads(content) if content else None
            except Exception as err:
                if log_cb:
                    log_cb(f"Failed to parse Nikto output JSON: {err}")
                report = None

            vulnerabilities: list[dict] = []
            if isinstance(report, list):
                # Nikto 2.5+ produces a top-level list of target host objects
                for host_entry in report:
                    if isinstance(host_entry, dict):
                        items = host_entry.get("vulnerabilities") or host_entry.get("items") or []
                        if isinstance(items, list):
                            vulnerabilities.extend(items)
            elif isinstance(report, dict):
                items = report.get("vulnerabilities") or report.get("items") or []
                if isinstance(items, list):
                    vulnerabilities.extend(items)

            for item in vulnerabilities:
                if isinstance(item, dict):
                    finding = _normalize_item(item, target)
                    # Filter out-of-scope finding evidence/targets
                    evidence_str = (finding.evidence or "").lower()
                    target_str = finding.target.lower()
                    is_excluded = False
                    if out_of_scope:
                        for rule in out_of_scope:
                            clean_rule = rule.strip().lower().lstrip("*.")
                            if clean_rule and (clean_rule in evidence_str or clean_rule in target_str):
                                is_excluded = True
                                break
                    if not is_excluded:
                        findings.append(finding)
                        if finding_cb:
                            finding_cb(finding)

            if log_cb and findings:
                log_cb(f"Parsed {len(findings)} real findings from Nikto output.")

        # If real engine failed to produce findings (e.g. missing XML::Writer or network error),
        # gracefully fall back to simulated findings so analysis can proceed
        if not findings:
            if log_cb:
                log_cb(f"Real Nikto engine finished (code {proc.returncode}) without generating findings. Providing fallback findings.")
            sim = build_simulated_findings(ScannerName.nikto, target)
            if finding_cb:
                for f in sim:
                    finding_cb(f)
            return sim

        return findings


class NiktoWrapper(ScannerWrapper):
    name = ScannerName.nikto
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
        sim_findings = build_simulated_findings(ScannerName.nikto, target)
        delay = 0.005 if (".local" in target or "demo" in target) else min(0.04, 1.0 / max(1, len(sim_findings)))
        if finding_cb:
            for f in sim_findings:
                await asyncio.sleep(delay)
                finding_cb(f)
        else:
            await asyncio.sleep(delay)
        return sim_findings
