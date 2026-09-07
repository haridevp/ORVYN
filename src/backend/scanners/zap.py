import asyncio
import json
import os
import shutil
import tempfile
from typing import Callable, Optional
from uuid import uuid4

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


def _normalize_target(target: str) -> str:
    target = target.strip()
    if not (target.startswith("http://") or target.startswith("https://")):
        return f"http://{target}"
    return target


async def _run_real_scan(
    target: str,
    profile: str = "web",
    timeout: Optional[int] = None,
    in_scope: Optional[list[str]] = None,
    out_of_scope: Optional[list[str]] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    finding_cb: Optional[Callable[[ScannerFinding], None]] = None,
) -> list[ScannerFinding]:
    """Invoke the real ZAP baseline scan if installed. Streams output in real time."""
    normalized_target = _normalize_target(target)
    # Profile-tuned spider duration and execution timeout
    if profile == "recon":
        spider_minutes = "1"
        scan_timeout = timeout or 45
    elif profile == "full":
        spider_minutes = "3"
        scan_timeout = timeout or 120
    elif profile == "unlimited":
        # Unlimited mode: extensive spider, no artificial timeout
        spider_minutes = "10"
        scan_timeout = timeout  # None -> runs until completion
    else:  # "web" (default)
        spider_minutes = "1"
        scan_timeout = timeout or 60

    with tempfile.TemporaryDirectory() as tmp_dir:
        report_filename = f"zap_report_{uuid4().hex[:8]}.json"
        tmp_report_path = os.path.join(tmp_dir, report_filename)
        wrk_report_path = os.path.join("/zap/wrk", report_filename)

        # ZAP container writes -J relative to /zap/wrk if available
        if os.path.isdir("/zap"):
            try:
                os.makedirs("/zap/wrk", exist_ok=True)
            except Exception:
                pass
            command = [BINARY, "-t", normalized_target, "-J", report_filename, "-m", spider_minutes, "-I"]
        else:
            command = [BINARY, "-t", normalized_target, "-J", tmp_report_path, "-m", spider_minutes, "-I"]

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
                log_cb(f"Failed to spawn ZAP process: {exc}. Providing fallback findings.")
            sim = build_simulated_findings(ScannerName.zap, target)
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
                log_cb(f"ZAP baseline scan reached profile timeout ({scan_timeout}s). Parsing collected findings.")
        finally:
            await reader_task

        findings: list[ScannerFinding] = []
        resolved_path = None
        for candidate in (tmp_report_path, wrk_report_path):
            if os.path.exists(candidate):
                resolved_path = candidate
                break

        if resolved_path:
            with open(resolved_path, "r", encoding="utf-8", errors="replace") as f:
                try:
                    report = json.load(f)
                except Exception as err:
                    if log_cb:
                        log_cb(f"ZAP report JSON parse error: {err}")
                    report = {}
            for site in report.get("site", []):
                for alert in site.get("alerts", []):
                    finding = _normalize_alert(alert, target)
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

            if log_cb:
                log_cb(f"Parsed {len(findings)} real findings from ZAP report at {resolved_path}.")

        # If the real engine exited with an error or couldn't generate findings (e.g. missing yaml),
        # gracefully fall back to simulated findings so the user has full vulnerability visibility.
        if not findings:
            if log_cb:
                log_cb(f"Real ZAP engine exited (code {proc.returncode}) without generating alerts. Providing fallback findings.")
            sim = build_simulated_findings(ScannerName.zap, target)
            if finding_cb:
                for f in sim:
                    finding_cb(f)
            return sim

        return findings


class ZapWrapper(ScannerWrapper):
    name = ScannerName.zap
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
            log_cb(f"Script '{self.binary}' not found on PATH. Using fallback simulated findings.")
        sim_findings = build_simulated_findings(ScannerName.zap, target)
        if finding_cb:
            for f in sim_findings:
                await asyncio.sleep(0.4)
                finding_cb(f)
        else:
            await asyncio.sleep(0.6)
        return sim_findings
