import asyncio
import os
import re
import shutil
import urllib.parse
from typing import Callable, Optional

from references import enrich_reference
from schemas import ScannerFinding, ScannerName, Severity
from scanners.base import ScannerWrapper
from scanners.cpe_knowledge import match_service_cves

BINARY = "nmap"


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

    # Broad port coverage for penetration testing
    ports = "21,22,23,25,53,80,110,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8000,8080,8443,8888,9200,27017" if profile in ("full", "unlimited") else "21,22,25,80,443,3306,8080,8443"
    
    nmap_args = [
        "-sV",
        "-Pn",
        "-T4",
        "--script=vulners,vuln,http-headers,http-methods,ssh2-enum-algos,ssl-enum-ciphers",
        "-p", ports,
        clean_host,
    ]
    command = wrapper.build_execution_command(nmap_args)

    if log_cb:
        log_cb(f"Executing: {' '.join(command)}")

    output_text = ""
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=240.0)
        output_text = stdout.decode("utf-8", errors="replace")
    except asyncio.TimeoutError:
        if log_cb:
            log_cb("Nmap scan timed out; parsing partial outputs.")
        try:
            proc.kill()
            stdout, _ = await proc.communicate()
            output_text = stdout.decode("utf-8", errors="replace") if stdout else ""
        except Exception:
            output_text = ""
    except Exception as exc:
        if log_cb:
            log_cb(f"Nmap execution error: {exc}")
        return []

    return parse_nmap_output(output_text, target, finding_cb=finding_cb)


def parse_nmap_output(
    output_text: str,
    target: str,
    finding_cb: Optional[Callable[[ScannerFinding], None]] = None,
) -> list[ScannerFinding]:
    clean_host = _clean_host(target)
    findings: list[ScannerFinding] = []
    seen_ids = set()

    # Regex patterns
    vuln_pattern = re.compile(r"^[|_][_\s\t]*([A-Za-z0-9\-_:]+)\s+([\d\.]+)\s+(https?://\S+)(.*)")
    port_pattern = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)")
    script_header_pattern = re.compile(r"^\|[_\s]([a-zA-Z0-9\-_]+):\s*(.*)")

    current_port = None
    current_service = None
    current_script = None
    current_block: list[str] = []
    discovered_banners: list[str] = []

    for raw_line in output_text.splitlines():
        line = raw_line.strip()

        # 1. Detect open ports and service banners
        p_match = port_pattern.match(line)
        if p_match:
            current_port = p_match.group(1)
            service_name = p_match.group(4)
            service_version = p_match.group(5).strip()
            current_service = f"{service_name} {service_version}".strip()
            discovered_banners.append(current_service)
            
            # Record exposed service finding
            service_finding_id = f"open-port-{current_port}"
            if service_finding_id not in seen_ids:
                seen_ids.add(service_finding_id)
                finding = ScannerFinding(
                    tool=ScannerName.nmap,
                    target=f"{clean_host}:{current_port}",
                    vulnerability=f"Exposed Service: {current_service} (Port {current_port}/{p_match.group(2)})",
                    severity=Severity.info,
                    description=f"Port {current_port}/{p_match.group(2)} is open running {current_service}.",
                    evidence=f"{p_match.group(0)}",
                    reference="https://nmap.org/book/man-version-detection.html",
                )
                findings.append(finding)
                if finding_cb:
                    finding_cb(finding)
            continue

        # 2. Detect Vulners discrete CVE / exploit records
        v_match = vuln_pattern.match(raw_line)
        if v_match:
            vuln_id, cvss_str, url, rest = v_match.groups()
            try:
                cvss = float(cvss_str)
            except ValueError:
                cvss = 5.0
            
            is_exploit = "*EXPLOIT*" in rest
            sev = (
                Severity.critical if cvss >= 9.0
                else Severity.high if cvss >= 7.0
                else Severity.medium if cvss >= 4.0
                else Severity.low if cvss > 0.0
                else Severity.info
            )

            dedup_key = f"{vuln_id}_{current_port}"
            if dedup_key not in seen_ids:
                seen_ids.add(dedup_key)
                exploit_suffix = " [VERIFIED EXPLOIT AVAILABLE]" if is_exploit else ""
                finding = ScannerFinding(
                    tool=ScannerName.nmap,
                    target=f"{clean_host}:{current_port}" if current_port else clean_host,
                    vulnerability=f"{vuln_id} ({current_service or 'Service Vulnerability'}){exploit_suffix}",
                    severity=sev,
                    description=f"Vulnerability {vuln_id} detected on {clean_host} ({current_service or 'network service'}). CVSS Score: {cvss}. Exploit available: {is_exploit}.",
                    evidence=f"{vuln_id} | CVSS {cvss} | {url}{' | *EXPLOIT*' if is_exploit else ''}",
                    reference=enrich_reference(vuln_id, url),
                )
                findings.append(finding)
                if finding_cb:
                    finding_cb(finding)
            continue

        # 3. Detect standard NSE script outputs (e.g. ssl-enum-ciphers, http-headers, vuln)
        s_match = script_header_pattern.match(line)
        if s_match:
            if current_script and current_block:
                block_text = "\n".join(current_block)
                if ("VULNERABLE" in block_text.upper() or "CVE-" in block_text.upper() or "BROKEN" in block_text.upper()) and current_script != "vulners":
                    script_key = f"{current_script}_{current_port}"
                    if script_key not in seen_ids:
                        seen_ids.add(script_key)
                        finding = ScannerFinding(
                            tool=ScannerName.nmap,
                            target=f"{clean_host}:{current_port}" if current_port else clean_host,
                            vulnerability=f"NSE: {current_script}",
                            severity=Severity.high if "CVE-" in block_text else Severity.medium,
                            description=block_text[:300],
                            evidence=block_text[:150],
                            reference=enrich_reference(current_script, f"https://nmap.org/nsedoc/scripts/{current_script}.html"),
                        )
                        findings.append(finding)
                        if finding_cb:
                            finding_cb(finding)
            current_script = s_match.group(1)
            current_block = [s_match.group(2)]
        elif current_script and line.startswith("|"):
            current_block.append(line.lstrip("|_ "))

    # 4. Fallback/Enrichment: If Vulners did not run (e.g. offline/network blocked), enrich detected banners with verified CVEs
    if len(findings) < 10 and discovered_banners:
        for banner in discovered_banners:
            cves = match_service_cves(banner)
            for c in cves:
                cve_id = c["cve"]
                if cve_id not in seen_ids:
                    seen_ids.add(cve_id)
                    finding = ScannerFinding(
                        tool=ScannerName.nmap,
                        target=f"{clean_host}",
                        vulnerability=f"{cve_id} ({banner}){' [VERIFIED EXPLOIT AVAILABLE]' if c.get('exploit') else ''}",
                        severity=c["severity"],
                        description=c["summary"],
                        evidence=f"Service banner: '{banner}' matches published {cve_id} (CVSS: {c['cvss']})",
                        reference=enrich_reference(cve_id, f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
                    )
                    findings.append(finding)
                    if finding_cb:
                        finding_cb(finding)

    return findings


class NmapWrapper(ScannerWrapper):
    name = ScannerName.nmap
    binary = BINARY
    parse_output = staticmethod(parse_nmap_output)

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
            log_cb(f"Starting Nmap scanner with vulners, vuln, and protocol NSE suites for target: {target}")
        return await _run_real_scan(
            target,
            wrapper=self,
            profile=profile,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            log_cb=log_cb,
            finding_cb=finding_cb,
        )
