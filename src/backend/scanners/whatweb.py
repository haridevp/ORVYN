import asyncio
import re
import shutil
import urllib.parse
from typing import Callable, Optional

from references import enrich_reference
from schemas import ScannerFinding, ScannerName, Severity
from scanners.base import ScannerWrapper

BINARY = "whatweb"


def _clean_host(target: str) -> str:
    cleaned = target.strip()
    if cleaned.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(cleaned)
        return parsed.hostname or cleaned
    return cleaned.split("/")[0].split(":")[0]


from scanners.cpe_knowledge import match_service_cves


async def _run_real_scan(
    target: str,
    wrapper: ScannerWrapper,
    profile: str = "web",
    in_scope: Optional[list[str]] = None,
    out_of_scope: Optional[list[str]] = None,
    log_cb: Optional[Callable[[str], None]] = None,
    finding_cb: Optional[Callable[[ScannerFinding], None]] = None,
) -> list[ScannerFinding]:
    target_url = target if target.startswith(("http://", "https://")) else f"http://{target}"
    clean_host = _clean_host(target)

    command = wrapper.build_execution_command([
        "--color=never",
        "-a", "1",
        target_url,
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
            log_cb(f"WhatWeb error: {exc}")
        return []

    findings: list[ScannerFinding] = []

    for line in output_text.splitlines():
        line = line.strip()
        if not line or "WhatWeb report" in line:
            continue

        plugins: list[str] = []
        cleaned_line = re.sub(r"^https?://[^\s]+\s+\[\d+\s+[^\]]+\]\s*", "", line)
        parts = [p.strip() for p in cleaned_line.split(", ") if p.strip()]
        for part in parts:
            if any(part.lower().startswith(skip) for skip in ("country[", "ip[", "http-date[")):
                continue
            plugins.append(part)

        for p in plugins:
            p_lower = p.lower()
            if p_lower.startswith("apache") or p_lower.startswith("nginx") or p_lower.startswith("httpserver"):
                is_outdated = any(old in p for old in ("2.4.7", "2.4.6", "2.2.", "2.0.", "1.14.", "1.10.", "1.8."))
                findings.append(ScannerFinding(
                    tool=ScannerName.whatweb,
                    target=target,
                    vulnerability="Web Server Software & Version Disclosure",
                    severity=Severity.medium if is_outdated else Severity.low,
                    description=f"Web server revealed internal component details: {p}. Version fingerprinting facilitates targeted exploit delivery.",
                    evidence=f"Component: {p} on {clean_host}",
                    reference=enrich_reference("Web Server Version Disclosure", "https://cwe.mitre.org/data/definitions/200.html"),
                ))

            elif p_lower.startswith("title["):
                title_text = p[6:-1] if p.endswith("]") else p
                findings.append(ScannerFinding(
                    tool=ScannerName.whatweb,
                    target=target,
                    vulnerability="Web Application Title & Identity Disclosed",
                    severity=Severity.info,
                    description=f"Public application page title identified: '{title_text}'.",
                    evidence=f"Title: {title_text}",
                    reference=enrich_reference("Information Disclosure", "https://capec.mitre.org/data/definitions/224.html"),
                ))

            elif any(p_lower.startswith(k) for k in ("php", "python", "ruby", "perl", "asp", "openssl")):
                findings.append(ScannerFinding(
                    tool=ScannerName.whatweb,
                    target=target,
                    vulnerability=f"Backend Runtime Fingerprinted: {p.split('[')[0]}",
                    severity=Severity.low,
                    description=f"Discovered backend technology environment: {p}.",
                    evidence=f"Technology: {p}",
                    reference=enrich_reference("Fingerprinting", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Server"),
                ))

        if plugins:
            tech_summary = ", ".join(plugins[:8])
            findings.append(ScannerFinding(
                tool=ScannerName.whatweb,
                target=target,
                vulnerability="Web Application Technology Stack Identified",
                severity=Severity.info,
                description=f"WhatWeb fingerprinting detected active technologies: {tech_summary}",
                evidence=f"Host: {clean_host} ({tech_summary})",
            ))
        # Enrich with CVEs for detected server versions
        for p in plugins:
            matched_cves = match_service_cves(p)
            for c in matched_cves:
                cve_id = c["cve"]
                findings.append(ScannerFinding(
                    tool=ScannerName.whatweb,
                    target=target,
                    vulnerability=f"{cve_id} ({p}){' [VERIFIED EXPLOIT AVAILABLE]' if c.get('exploit') else ''}",
                    severity=c["severity"],
                    description=c["summary"],
                    evidence=f"WhatWeb fingerprinted banner: '{p}' matching {cve_id} (CVSS: {c['cvss']})",
                    reference=enrich_reference(cve_id, f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
                ))

    for f in findings:
        if finding_cb:
            finding_cb(f)

    return findings


class WhatWebWrapper(ScannerWrapper):
    name = ScannerName.whatweb
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
            log_cb(f"Executing WhatWeb scanner for target: {target}")
        return await _run_real_scan(
            target,
            wrapper=self,
            profile=profile,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            log_cb=log_cb,
            finding_cb=finding_cb,
        )
