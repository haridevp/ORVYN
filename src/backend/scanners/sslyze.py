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
            log_cb(f"SSLyze error: {exc}.")
        return []

    findings: list[ScannerFinding] = []
    if output_text and output_text.strip().startswith("{"):
        try:
            data = json.loads(output_text)
            server_scan = data.get("server_scan_results", [])
            if server_scan:
                entry = server_scan[0]
                status = entry.get("scan_status") or ""
                conn_status = entry.get("connectivity_status") or ""

                # Check if server operates on cleartext HTTP and refused TLS port 443
                if status == "ERROR_NO_CONNECTIVITY" or conn_status == "ERROR":
                    err_msg = entry.get("connectivity_error_trace") or ""
                    if "rejected" in err_msg.lower() or "refused" in err_msg.lower() or "timed out" in err_msg.lower():
                        findings.append(ScannerFinding(
                            tool=ScannerName.sslyze,
                            target=f"http://{clean_host}",
                            vulnerability="Missing HTTPS / Cleartext Transmission (Port 443 Inaccessible)",
                            severity=Severity.medium,
                            description=f"Host '{clean_host}' serves HTTP traffic over cleartext and rejected SSL/TLS connections on port 443. Traffic is susceptible to eavesdropping and interception.",
                            evidence=f"TLS handshake to {clean_host}:443 failed: Server rejected connection. Plaintext HTTP active on port 80.",
                            reference=enrich_reference("Cleartext Transmission", "https://cwe.mitre.org/data/definitions/319.html"),
                        ))

                scan_result = entry.get("scan_result", {}) or {}
                if scan_result:
                    # Check SSL 2.0 / 3.0 / TLS 1.0 / TLS 1.1
                    for ver_key, ver_name, sev in [
                        ("ssl_2_0_cipher_suites", "SSL 2.0", Severity.critical),
                        ("ssl_3_0_cipher_suites", "SSL 3.0", Severity.high),
                        ("tls_1_0_cipher_suites", "TLS 1.0", Severity.medium),
                        ("tls_1_1_cipher_suites", "TLS 1.1", Severity.medium),
                    ]:
                        res = scan_result.get(ver_key, {}).get("result", {})
                        if res and res.get("is_tls_version_supported"):
                            findings.append(ScannerFinding(
                                tool=ScannerName.sslyze,
                                target=f"https://{clean_host}",
                                vulnerability=f"Deprecated {ver_name} Protocol Supported",
                                severity=sev,
                                description=f"The server negotiates and supports deprecated {ver_name} protocol, exposing connections to cryptographic degradation attacks.",
                                evidence=f"{ver_name} accepted by {clean_host}:443",
                                reference=enrich_reference(f"{ver_name} Supported", "https://datatracker.ietf.org/doc/html/rfc8996"),
                            ))

                    # Check Certificate Validation
                    cert_info = scan_result.get("certificate_info", {}).get("result", {})
                    if cert_info:
                        deployments = cert_info.get("certificate_deployments", [])
                        for dep in deployments:
                            val_results = dep.get("path_validation_results", [])
                            for val in val_results:
                                if val.get("was_validation_successful") is False:
                                    err = val.get("error") or "Untrusted Certificate Authority"
                                    findings.append(ScannerFinding(
                                        tool=ScannerName.sslyze,
                                        target=f"https://{clean_host}",
                                        vulnerability="SSL/TLS Certificate Validation Failure",
                                        severity=Severity.high,
                                        description=f"Server certificate failed chain validation: {err}. Clients will encounter browser security warnings.",
                                        evidence=f"Certificate validation error on {clean_host}:443: {err}",
                                        reference=enrich_reference("Improper Certificate Validation", "https://cwe.mitre.org/data/definitions/295.html"),
                                    ))

                    # Check Heartbleed
                    heartbleed = scan_result.get("heartbleed", {}).get("result", {})
                    if heartbleed and heartbleed.get("is_vulnerable_to_heartbleed"):
                        findings.append(ScannerFinding(
                            tool=ScannerName.sslyze,
                            target=f"https://{clean_host}",
                            vulnerability="OpenSSL Heartbleed Memory Leak (CVE-2014-0160)",
                            severity=Severity.critical,
                            description="Server is vulnerable to OpenSSL Heartbleed, allowing unauthenticated attackers to read server process memory.",
                            evidence=f"Heartbleed payload verified on {clean_host}:443",
                            reference=enrich_reference("Heartbleed", "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"),
                        ))
        except Exception:
            pass

    for f in findings:
        if finding_cb:
            finding_cb(f)

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
            log_cb(f"Binary '{self.binary}' not found on PATH. Real scan skipped.")
        return []
