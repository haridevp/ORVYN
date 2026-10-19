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
    template_tags: Optional[str] = None,
    template_ids: Optional[str] = None,
) -> list[ScannerFinding]:
    """Invoke the real `nuclei` binary if it's installed. Streams verbose execution logs and live findings."""
    target_url = target if target.startswith(("http://", "https://")) else f"http://{target}"

    # Default to fast, targeted tags or LLM-selected tags to avoid hanging on 6,000+ templates
    tags = template_tags or "tech,exposure,misconfig,cve"
    scan_timeout = timeout or 45

    extra_args = [
        "-tags", tags,
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "-timeout", "3",
        "-rate-limit", "25",
        "-concurrency", "10",
        "-retries", "1",
    ]

    if template_ids:
        extra_args.extend(["-id", template_ids])

    # Exclude out-of-scope hosts
    if out_of_scope:
        exclude_hosts = [r.strip().lstrip("*.") for r in out_of_scope if "/" not in r and r.strip()]
        if exclude_hosts:
            extra_args.extend(["-exclude-hosts", ",".join(exclude_hosts)])

    findings: list[ScannerFinding] = []
    seen_vulns = set()

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_file = os.path.join(tmp_dir, "nuclei_output.json")
        command = [
            BINARY,
            "-u", target_url,
            "-duc",  # disable update check to prevent waiting on github api
            "-j",    # jsonl format
            "-o", output_file,
            "-no-color",
            "-v",
            *extra_args,
        ]
        timeout_label = f"{scan_timeout}s" if scan_timeout is not None else "UNLIMITED"
        if log_cb:
            log_cb(f"Executing: {' '.join(command)} (timeout: {timeout_label}, tags: {tags})")

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as exc:
            if log_cb:
                log_cb(f"Failed to spawn Nuclei process: {exc}.")
            return []

        async def read_stream():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                # Try parsing real-time json finding from stream
                if text.startswith("{") and ("\"template-id\"" in text or "\"info\"" in text):
                    try:
                        parsed = json.loads(text)
                        finding = _normalize_raw_line(parsed, target)
                        if finding and (finding.vulnerability, finding.evidence) not in seen_vulns:
                            seen_vulns.add((finding.vulnerability, finding.evidence))
                            findings.append(finding)
                            if finding_cb:
                                finding_cb(finding)
                            if log_cb:
                                log_cb(f"🎯 Nuclei finding: [{finding.severity.upper()}] {finding.vulnerability} at {finding.evidence}")
                            continue
                    except Exception:
                        pass
                if log_cb:
                    log_cb(text)

        reader_task = asyncio.create_task(read_stream())
        try:
            if scan_timeout is not None:
                await asyncio.wait_for(proc.wait(), timeout=scan_timeout)
            else:
                await proc.wait()
        except asyncio.TimeoutError:
            try:
                proc.terminate()
                await asyncio.sleep(1)
                if proc.returncode is None:
                    proc.kill()
            except Exception:
                pass
            if log_cb:
                log_cb(f"Nuclei execution reached profile timeout ({scan_timeout}s). Wrapping up {len(findings)} available findings.")
        finally:
            if not reader_task.done():
                try:
                    await asyncio.wait_for(reader_task, timeout=1.5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    reader_task.cancel()

        # Also read output file for any lines not captured in stdout
        if os.path.exists(output_file):
            try:
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
                                if finding and (finding.vulnerability, finding.evidence) not in seen_vulns:
                                    seen_vulns.add((finding.vulnerability, finding.evidence))
                                    findings.append(finding)
                                    if finding_cb:
                                        finding_cb(finding)
            except Exception as e:
                if log_cb:
                    log_cb(f"Note reading output file: {e}")

        if not findings and proc.returncode != 0:
            if log_cb:
                log_cb(f"Nuclei finished (code {proc.returncode}). No vulnerabilities identified.")

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
        **kwargs,
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
                template_tags=kwargs.get("template_tags"),
                template_ids=kwargs.get("template_ids"),
            )

        if log_cb:
            log_cb(f"Binary '{self.binary}' not found on PATH. Real scan skipped.")
        return []

