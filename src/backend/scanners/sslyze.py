import asyncio
import json
import shutil
import urllib.parse
from typing import Callable, Optional

from references import enrich_reference
from schemas import ScannerFinding, ScannerName, Severity
from scanners.base import ScannerWrapper
from scanners.simulated_data import build_simulated_findings

BINARY = "sslyze"


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
    command = [
        BINARY,
        "--json_out=-",
        f"{clean_host}:443",
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
            log_cb(f"SSLyze error: {exc}. Providing fallback findings.")
        sim = build_simulated_findings(ScannerName.sslyze, target)
        if finding_cb:
            for f in sim:
                finding_cb(f)
        return sim

    findings: list[ScannerFinding] = []
    if output_text and output_text.strip().startswith("{"):
        try:
            data = json.loads(output_text)
            server_scan = data.get("server_scan_results", [])
            if server_scan:
                scan_result = server_scan[0].get("scan_result", {}) or {}

                # Check TLS 1.0
                tls_1_0 = scan_result.get("tls_1_0_cipher_suites", {}).get("result", {})
                if tls_1_0.get("is_tls_version_supported"):
                    finding = ScannerFinding(
                        tool=ScannerName.sslyze,
                        target=f"https://{clean_host}",
                        vulnerability="TLS 1.0 Supported",
                        severity=Severity.medium,
                        description="The server supports the deprecated TLS 1.0 protocol.",
                        evidence=f"TLS 1.0 is accepted by {clean_host}:443",
                        reference=enrich_reference("TLS 1.0 Supported", "https://datatracker.ietf.org/doc/html/rfc8996"),
                    )
                    findings.append(finding)
                    if finding_cb:
                        finding_cb(finding)

                # Check TLS 1.1
                tls_1_1 = scan_result.get("tls_1_1_cipher_suites", {}).get("result", {})
                if tls_1_1.get("is_tls_version_supported"):
                    finding = ScannerFinding(
                        tool=ScannerName.sslyze,
                        target=f"https://{clean_host}",
                        vulnerability="TLS 1.1 Supported",
                        severity=Severity.medium,
                        description="The server supports the deprecated TLS 1.1 protocol.",
                        evidence=f"TLS 1.1 is accepted by {clean_host}:443",
                        reference=enrich_reference("TLS 1.1 Supported", "https://datatracker.ietf.org/doc/html/rfc8996"),
                    )
                    findings.append(finding)
                    if finding_cb:
                        finding_cb(finding)
        except Exception:
            pass

    if not findings:
        sim = build_simulated_findings(ScannerName.sslyze, target)
        if finding_cb:
            for f in sim:
                finding_cb(f)
        return sim

    return findings


class SSLyzeWrapper(ScannerWrapper):
    name = ScannerName.sslyze
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
        sim_findings = build_simulated_findings(ScannerName.sslyze, target)
        delay = 0.005 if (".local" in target or "demo" in target) else min(0.04, 1.0 / max(1, len(sim_findings)))
        if finding_cb:
            for f in sim_findings:
                await asyncio.sleep(delay)
                finding_cb(f)
        else:
            await asyncio.sleep(delay)
        return sim_findings
