import asyncio
import json
import shutil
import urllib.parse
from typing import Callable, Optional

from references import enrich_reference
from schemas import ScannerFinding, ScannerName, Severity
from scanners.base import ScannerWrapper

BINARY = "sslyze"


def _clean_host(target: str) -> str:
    cleaned = target.strip()
    if cleaned.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(cleaned)
        return parsed.hostname or cleaned
    return cleaned.split("/")[0].split(":")[0]


async def _run_real_scan(
    target: str,
    wrapper: ScannerWrapper,
    profile: str = "web",
    in_scope: Optional[list[str]] = None,
    out_of_scope: Optional[list[str]] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    finding_cb: Optional[Callable[[ScannerFinding], None]] = None,
) -> list[ScannerFinding]:
    clean_host = _clean_host(target)
    command = wrapper.build_execution_command([
        "--json_out=-",
        f"{clean_host}:443",
    ])

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
            log_cb(f"SSLyze error: {exc}")
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
                            vulnerability="Missing HTTPS / Cleartext HTTP Transport Exposed",
                            severity=Severity.medium,
                            description=f"SSLyze port 443 probe encountered refusal or timeout: {err_msg[:120]}. Host communicates without enforced TLS transport encryption.",
                            evidence=f"Refused TLS on port 443 ({err_msg[:80]})",
                            reference=enrich_reference("Insecure Transport", "https://cwe.mitre.org/data/definitions/319.html"),
                        ))

                # Check SSL/TLS protocol deployments
                scan_commands = entry.get("scan_commands_results", {})
                
                # Check for deprecated SSLv2 / SSLv3 / TLSv1.0 / TLSv1.1
                for proto in ("ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites", "tls_1_0_cipher_suites", "tls_1_1_cipher_suites"):
                    proto_res = scan_commands.get(proto, {})
                    if proto_res.get("accepted_cipher_suites"):
                        proto_name = proto.replace("_cipher_suites", "").replace("_", ".").upper()
                        findings.append(ScannerFinding(
                            tool=ScannerName.sslyze,
                            target=f"https://{clean_host}:443",
                            vulnerability=f"Deprecated {proto_name} Cryptographic Protocol Supported",
                            severity=Severity.high if "SSL" in proto_name else Severity.medium,
                            description=f"Server accepts connections using deprecated cryptographic protocol {proto_name}, subject to POODLE, BEAST, and downgrade attacks.",
                            evidence=f"Accepted ciphers under {proto_name}",
                            reference=enrich_reference("Broken or Risky Cryptographic Algorithm", "https://cwe.mitre.org/data/definitions/327.html"),
                        ))

                # Check Certificate Deployment and Validity
                cert_res = scan_commands.get("certificate_info", {})
                cert_deployments = cert_res.get("certificate_deployments", [])
                if cert_deployments:
                    cert = cert_deployments[0]
                    val_results = cert.get("path_validation_results", [])
                    has_error = any(v.get("was_validation_successful") is False for v in val_results)
                    if has_error:
                        findings.append(ScannerFinding(
                            tool=ScannerName.sslyze,
                            target=f"https://{clean_host}:443",
                            vulnerability="Untrusted or Expired TLS Certificate Deployment",
                            severity=Severity.medium,
                            description="SSLyze certificate chain validation failed against standard Mozilla trust stores. Potential self-signed or expired certificate in production.",
                            evidence=f"Failed trust validation for {clean_host}",
                            reference=enrich_reference("Improper Certificate Validation", "https://cwe.mitre.org/data/definitions/295.html"),
                        ))

                # Heartbleed vulnerability check
                hb_res = scan_commands.get("heartbleed", {})
                if hb_res.get("is_vulnerable_to_heartbleed"):
                    findings.append(ScannerFinding(
                        tool=ScannerName.sslyze,
                        target=f"https://{clean_host}:443",
                        vulnerability="OpenSSL Heartbleed TLS Information Disclosure (CVE-2014-0160)",
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
        if not self.is_available():
            if log_cb:
                log_cb(f"Binary '{self.binary}' not found and container execution unavailable.")
            return []

        if log_cb:
            log_cb(f"Executing SSLyze scanner for target: {target}")
        return await _run_real_scan(
            target,
            wrapper=self,
            profile=profile,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            log_cb=log_cb,
            finding_cb=finding_cb,
        )
