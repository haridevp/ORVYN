import subprocess
import json
import os
import sys
import argparse
import re
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

# =====================================================================
# CROSS-PLATFORM PATHS & NORMALIZERS
# =====================================================================
TEMP_DIR = tempfile.gettempdir()

def resolve_binary(binary_name: str) -> str:
    """Dynamically resolves executable paths across any OS without hardcoded strings."""
    found = shutil.which(binary_name)
    if found:
        return found

    python_script_dirs = [
        Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin"),
        Path(sys.base_prefix) / ("Scripts" if os.name == "nt" else "bin"),
        Path(os.environ.get("APPDATA", "")) / "Python" / f"Python{sys.version_info.major}{sys.version_info.minor}" / "Scripts",
        Path.home() / ".local" / "bin",
        Path.home() / "go" / "bin"
    ]

    system_env_roots = []
    if "PROGRAMFILES" in os.environ:
        system_env_roots.append(Path(os.environ["PROGRAMFILES"]))
    if "PROGRAMFILES(X86)" in os.environ:
        system_env_roots.append(Path(os.environ["PROGRAMFILES(X86)"]))
    if "LOCALAPPDATA" in os.environ:
        system_env_roots.append(Path(os.environ["LOCALAPPDATA"]) / "Microsoft" / "WinGet" / "Links")
    if "HOME" in os.environ:
        system_env_roots.extend([
            Path(os.environ["HOME"]) / "bin",
            Path("/opt"),
            Path("/usr/local/bin")
        ])

    candidate_dirs = python_script_dirs + system_env_roots
    extensions = ["", ".exe", ".bat", ".cmd", ".sh"] if os.name == "nt" else ["", ".sh"]

    for base_dir in candidate_dirs:
        if not base_dir.exists():
            continue
        for ext in extensions:
            target = base_dir / f"{binary_name}{ext}"
            if target.is_file() and os.access(target, os.X_OK):
                return str(target)
            
            for sub_dir in base_dir.iterdir():
                if sub_dir.is_dir():
                    sub_target = sub_dir / f"{binary_name}{ext}"
                    if sub_target.is_file() and os.access(sub_target, os.X_OK):
                        return str(sub_target)

    return ""

def strip_ansi(text: str) -> str:
    if not text:
        return ""
    ansi_regex = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    cleaned = ansi_regex.sub('', str(text))
    return cleaned.replace('\r', '').strip()

def format_standard_finding(
    tool: str,
    target: str,
    vulnerability: str,
    severity: str,
    description: str,
    evidence: str = "",
    reference: str = ""
) -> Dict[str, Any]:
    return {
        "tool": strip_ansi(tool),
        "target": strip_ansi(target),
        "vulnerability": strip_ansi(vulnerability),
        "severity": severity.lower() if isinstance(severity, str) else "info",
        "description": strip_ansi(description) if description else "No detailed description provided.",
        "evidence": strip_ansi(evidence),
        "reference": strip_ansi(reference) if reference else "N/A"
    }

def parse_target(input_url: str) -> Tuple[str, str]:
    """
    Resolves the target protocol automatically when the user provides
    only a hostname.

    Explicit http:// or https:// is always respected.
    For a bare hostname, HTTPS is tried first, then HTTP.
    """

    url = input_url.strip()

    # ---------------------------------------------------------
    # Explicit scheme supplied by user
    # ---------------------------------------------------------
    if url.startswith("http://") or url.startswith("https://"):
        full_url = url

    else:
        # -----------------------------------------------------
        # No scheme supplied:
        # Try HTTPS first
        # -----------------------------------------------------
        https_url = f"https://{url}"
        http_url = f"http://{url}"

        try:
            parsed = urlparse(https_url)
            host = parsed.hostname
            port = parsed.port

            if port:
                connection_port = port
            else:
                connection_port = 443

            import socket

            with socket.create_connection(
                (host, connection_port),
                timeout=5
            ):
                full_url = https_url

        except Exception:
            # -------------------------------------------------
            # HTTPS unavailable → try HTTP
            # -------------------------------------------------
            try:
                parsed = urlparse(http_url)
                host = parsed.hostname
                port = parsed.port

                if port:
                    connection_port = port
                else:
                    connection_port = 80

                import socket

                with socket.create_connection(
                    (host, connection_port),
                    timeout=5
                ):
                    full_url = http_url

            except Exception:
                # -------------------------------------------------
                # Neither protocol reachable.
                # Default to HTTPS so scanners receive a valid URL.
                # -------------------------------------------------
                full_url = https_url

    # ---------------------------------------------------------
    # Extract clean hostname
    # ---------------------------------------------------------
    parsed = urlparse(full_url)
    clean_host = parsed.hostname or ""

    return full_url, clean_host

def safe_run_command(cmd_list: List[str], timeout: int = None) -> Tuple[str, str]:
    """Universal process runner handling binary resolution, timeouts, and missing tools."""

    cmd = list(cmd_list)   # Make a copy — don't modify original list

    binary_name = cmd[0]
    resolved_path = resolve_binary(binary_name)

    if not resolved_path:
        return "", f"Scanner '{binary_name}' is not installed or not discoverable."

    cmd[0] = resolved_path

    try:
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            shell=False
        )


        return res.stdout or "", res.stderr or ""

    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="ignore")

        return stdout, "Execution reached timeout limit (partial stdout rescued)."

    except Exception as e:
        return "", str(e)


# =====================================================================
# 1. NUCLEI WRAPPER
# =====================================================================
def run_nuclei_scan(target_url: str, clean_host: str) -> List[Dict[str, Any]]:

    findings = []

    print(f"[*] [1/7] Running Nuclei on {target_url}...")

    nuclei_path = shutil.which("nuclei")

    if not nuclei_path:
        print("    [!] ERROR: Nuclei binary not found.")
        return findings

    command = [
    "nuclei",
    "-u", target_url,
    "-jsonl",
    ]

    stdout, err = safe_run_command(command, timeout=None)

    # Parse JSONL findings
    if stdout:

        for line in stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)

            except json.JSONDecodeError:
                print(f"    [!] Invalid JSON line skipped: {line[:100]}")
                continue

            template_id = data.get("template-id", "unknown")

            info = data.get("info", {})

            severity = str(
                info.get("severity", "info")
            ).lower()

            matched_target = data.get(
                "matched-at",
                target_url
            )

            description = info.get(
                "name",
                f"Nuclei match: {template_id}"
            )

            # Reference can be a list
            ref = info.get("reference", "N/A")

            if isinstance(ref, list):
                ref = ", ".join(str(x) for x in ref)

            # Evidence
            extracted = data.get("extracted-results", [])

            if isinstance(extracted, list) and extracted:

                evidence_val = ", ".join(
                    str(x) for x in extracted[:3]
                )

            else:

                evidence_val = data.get(
                    "matcher-name",
                    data.get("type", "match")
                )

            findings.append(
                format_standard_finding(
                    tool="Nuclei",
                    target=str(matched_target),
                    vulnerability=str(template_id),
                    severity=severity,
                    description=str(description),
                    evidence=str(evidence_val),
                    reference=str(ref)
                )
            )

    print(f"    [+] Nuclei findings: {len(findings)}")

    return findings

# =====================================================================
# 2. NIKTO WRAPPER
# =====================================================================
def run_nikto_scan(target_url: str, clean_host: str) -> List[Dict[str, Any]]:
    findings = []

    # ---------------------------------------------------------
    # Parse target URL
    # ---------------------------------------------------------

    parsed = urlparse(target_url)

    scheme = parsed.scheme.lower()

    # Default to HTTPS if scheme is missing
    if scheme not in ("http", "https"):
        scheme = "https"

    # Use explicit port from URL if provided
    try:
        target_port = parsed.port
    except ValueError:
        print("    [!] Invalid port in target URL.")
        return findings

    if target_port:
        port = target_port
    else:
        port = 443 if scheme == "https" else 80

    use_ssl = scheme == "https"
    protocol_name = "HTTPS" if use_ssl else "HTTP"

    
    print(f"[*] [2/7] Running Nikto on {target_url}...")

    # ---------------------------------------------------------
    # Build Nikto command
    # ---------------------------------------------------------

    cmd = [
        "nikto",
        "-h", clean_host,
        "-p", str(port),
        "-nointeractive",
        "-nocheck"
    ]

    if use_ssl:
        cmd.append("-ssl")

    # ---------------------------------------------------------
    # Run Nikto
    # ---------------------------------------------------------

    stdout, stderr = safe_run_command(
        cmd,
        timeout=None
    )

    # ---------------------------------------------------------
    # Nikto metadata / status messages to ignore
    # ---------------------------------------------------------

    ignore_prefixes = [
        "target ip:",
        "target hostname:",
        "target port:",
        "start time:",
        "end time:",
        "server:",
        "nikto v",
        "multiple ips found:",
        "no cgi directories found",
        "scan terminated:",
        "0 host(s) tested",
        "1 host(s) tested",
        "no web server found",
        "error:",
        "ssl info:",
        "platform:",
        "osvdb",
    ]

    # Messages that are scan summaries, not findings
    summary_patterns = [
        r"^\d+\s+requests?:",
        r"^\d+\s+items?\s+reported",
        r"^\d+\s+errors?\s+and\s+\d+\s+items?\s+reported",
    ]

    # ---------------------------------------------------------
    # Process Nikto output
    # ---------------------------------------------------------

    seen_findings = set()

    for line in stdout.splitlines():

        line = strip_ansi(line).strip()

        # Nikto findings normally begin with "+ "
        if not line.startswith("+ "):
            continue

        msg = line[2:].strip()

        if not msg or len(msg) < 5:
            continue

        msg_lower = msg.lower()

        # -----------------------------------------------------
        # Ignore scanner metadata / noise
        # -----------------------------------------------------

        if any(
            msg_lower.startswith(prefix)
            for prefix in ignore_prefixes
        ):
            continue

        # Ignore separator lines
        if set(msg) <= {"-", "=", "_"}:
            continue

        # Ignore summary lines
        if any(
            re.search(pattern, msg_lower)
            for pattern in summary_patterns
        ):
            continue

        # -----------------------------------------------------
        # HTTP-specific filtering
        # HSTS is only meaningful over HTTPS
        # -----------------------------------------------------

        if not use_ssl:
            if (
                "strict-transport-security" in msg_lower
                or "hsts" in msg_lower
            ):
                continue

        # -----------------------------------------------------
        # Extract Nikto test ID
        # Example: [007303]
        # -----------------------------------------------------

        nikto_id_match = re.search(
            r"\[(\d+)\]",
            msg
        )

        if nikto_id_match:
            nikto_id = nikto_id_match.group(1)
            reference = f"Nikto-{nikto_id}"
        else:
            reference = "Nikto-N/A"

        # -----------------------------------------------------
        # Determine severity
        # -----------------------------------------------------

        severity = "info"

        # Critical severity
        critical_keywords = [
            "remote code execution",
            "arbitrary code execution",
            "command execution",
            "command injection",
            "remote shell",
            "web shell",
        ]

        # High severity
        high_keywords = [
            "sql injection",
            "authentication bypass",
            "directory traversal",
            "path traversal",
            "file inclusion",
            "remote file inclusion",
            "local file inclusion",
            "privilege escalation",
        ]

        # Medium severity
        medium_keywords = [
            "cross-site scripting",
            "xss vulnerability",
            "vulnerabilities",
            "vulnerability",
            "admin interface",
            "administrative interface",
            "sensitive information",
            "information disclosure",
            "exposed database",
            "directory listing",
        ]

        # Low severity
        low_keywords = [
            "suggested security header missing",
            "header is not set",
            "hostname",
            "certificate",
            "deprecated",
            "missing",
        ]

        if any(
            keyword in msg_lower
            for keyword in critical_keywords
        ):
            severity = "critical"

        elif any(
            keyword in msg_lower
            for keyword in high_keywords
        ):
            severity = "high"

        elif any(
            keyword in msg_lower
            for keyword in medium_keywords
        ):
            severity = "medium"

        elif any(
            keyword in msg_lower
            for keyword in low_keywords
        ):
            severity = "low"

        # -----------------------------------------------------
        # Create deduplication key
        # Keep port/protocol separate
        # -----------------------------------------------------

        dedup_key = (
            clean_host.lower(),
            port,
            protocol_name,
            msg_lower
        )

        if dedup_key in seen_findings:
            continue

        seen_findings.add(dedup_key)


        # -----------------------------------------------------
        # Store standardized finding
        # -----------------------------------------------------

        findings.append(
            format_standard_finding(
                tool="Nikto",
                target=target_url,
                vulnerability="Nikto Web Finding",
                severity=severity,
                description=msg,
                evidence=(
                    f"Host: {clean_host}:{port} "
                    f"({protocol_name})"
                ),
                reference=reference
            )
        )

    print(f"    [+] Nikto findings: {len(findings)}")

    return findings


# =====================================================================
# 3. OWASP ZAP WRAPPER
# =====================================================================
def run_zap_scan(target_url: str) -> List[Dict[str, Any]]:
    output_file = os.path.join(TEMP_DIR, "temp_zap_results.json")
    if os.path.exists(output_file):
        os.remove(output_file)

    findings = []
    zap_bin = (
        shutil.which("zaproxy") or
        shutil.which("zap.sh") or
        shutil.which("zap.bat") or
        shutil.which("zap")
    )

    print(f"[*] [3/7] Running OWASP ZAP on {target_url}...")
    if zap_bin:
        safe_run_command([zap_bin, "-cmd", "-quickurl", target_url, "-quickout", output_file], timeout=None)

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            try:
                with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                    alerts_list = []
                    if isinstance(data, dict):
                        if "alerts" in data and isinstance(data["alerts"], list):
                            alerts_list = data["alerts"]
                        elif "site" in data and isinstance(data["site"], list) and len(data["site"]) > 0:
                            alerts_list = data["site"][0].get("alerts", [])

                    for alert in alerts_list:
                        if not isinstance(alert, dict):
                            continue
                        findings.append(format_standard_finding(
                            tool="OWASP ZAP",
                            target=target_url,
                            vulnerability=alert.get("name", alert.get("alert", "ZAP Finding")),
                            severity=alert.get("riskdesc", alert.get("risk", "Info")).split()[0],
                            description=alert.get("desc", alert.get("description", "")),
                            evidence=alert.get("evidence", alert.get("solution", "")),
                            reference=alert.get("solution", "N/A")
                        ))
            except Exception:
                pass
            finally:
                if os.path.exists(output_file):
                    os.remove(output_file)

    print(f"    [+] OWASP ZAP findings: {len(findings)}")
    return findings


# =====================================================================
# 4. WHATWEB WRAPPER
# =====================================================================
def run_whatweb_scan(target_url: str, clean_host: str) -> List[Dict[str, Any]]:
    findings = []

    print(f"[*] [4/7] Running WhatWeb on {target_url}...")

    stdout, err = safe_run_command(
        [
            "whatweb",
            "--color=never",
            "-a", "1",
            target_url
        ],
        timeout=None
    )

    if stdout:
        for line in stdout.splitlines():
            line = strip_ansi(line).strip()

            if not line:
                continue

            # Ignore plain HTTP response metadata
            if "[200 OK]" in line and "Country[" in line and "IP[" in line:
                continue

        # If WhatWeb only returned the target + HTTP status,
        # there is nothing useful to record.
            if "[200 OK]" in line and "Country[" not in line:
                continue

            # WhatWeb normally reports detected technologies
            # inside the result after the target/HTTP status.
            if any(keyword in line.lower() for keyword in [
                "country:",
                "ip:",
                "http status:",
                "whatweb"
            ]):
                continue

            # Only create a standardized finding if there is
            # an actual technology/fingerprint to report.
            description = line

            if description:
                findings.append(
                    format_standard_finding(
                        tool="WhatWeb",
                        target=target_url,
                        vulnerability="Web Technology Stack Fingerprint",
                        severity="info",
                        description=description,
                        evidence=f"Host: {clean_host}",
                        reference="https://github.com/urbanadventurer/WhatWeb"
                    )
                )

    print(f"    [+] WhatWeb findings: {len(findings)}")

    return findings
# =====================================================================
# 5. NMAP VULN WRAPPER
# =====================================================================
def run_nmap_vuln_scan(target_url: str, clean_host: str) -> List[Dict[str, Any]]:
    findings = []

    print(f"[*] [5/7] Running Nmap on {clean_host}...")

    # ---------------------------------------------------------
    # Build Nmap command
    # ---------------------------------------------------------

    command = [
        "nmap",
        "-sV",
        "-T4",
        "--script=vuln",
        "-p", "22,80,443",
        clean_host
    ]

    # ---------------------------------------------------------
    # Run Nmap
    # ---------------------------------------------------------

    stdout, err = safe_run_command(
        command,
        timeout=None
    )


    # ---------------------------------------------------------
    # Handle errors
    # ---------------------------------------------------------

    if not stdout:

        print("    [!] Nmap returned no output.")

        if err:
            print(f"    [!] Nmap error: {err}")

        return findings

    # ---------------------------------------------------------
    # Parse NSE script blocks
    # ---------------------------------------------------------

    lines = stdout.splitlines()

    current_script = None
    current_block = []

    script_blocks = []

    for raw_line in lines:

        line = strip_ansi(raw_line)

        script_match = re.match(
           r"^\|_?\s?([a-zA-Z0-9_-]+):\s*(.*)$",
           line
        )

        if script_match:

            # Save previous script block
            if current_script and current_block:

                script_blocks.append(
                    (
                        current_script,
                        current_block
                    )
                )

            current_script = script_match.group(1)

            current_block = [line]

            continue

        # -----------------------------------------------------
        # Continue collecting lines belonging to current script
        # -----------------------------------------------------

        if current_script:

            if line.strip().startswith("|"):

                current_block.append(line)

            else:

                # Script block ended
                if current_block:

                    script_blocks.append(
                        (
                            current_script,
                            current_block
                        )
                    )

                current_script = None
                current_block = []

    # Save final block

    if current_script and current_block:

        script_blocks.append(
            (
                current_script,
                current_block
            )
        )

    # ---------------------------------------------------------
    # Analyze each script block
    # ---------------------------------------------------------

    seen = set()

    for script_name, block_lines in script_blocks:

        # Combine entire block

        block_text = "\n".join(block_lines)

        block_lower = block_text.lower()

        # -----------------------------------------------------
        # Ignore scripts that explicitly report no vulnerability
        # -----------------------------------------------------

        negative_indicators = [

            "couldn't find any",

            "no vulnerabilities found",

            "not vulnerable",

            "safe"
        ]

        if any(
            indicator in block_lower
            for indicator in negative_indicators
        ):
            continue

        # -----------------------------------------------------
        # Only keep vulnerability-related blocks
        # -----------------------------------------------------

        vulnerability_indicators = ["state: vulnerable",

        "state: likely vulnerable",

        "vulnerable:"
        ]

        if not any(
            indicator in block_lower
            for indicator in vulnerability_indicators
        ):
            continue

        # -----------------------------------------------------
        # Determine severity
        # -----------------------------------------------------

        severity = "info"

        if "state: vulnerable" in block_lower:

            severity = "high"

        elif "likely vulnerable" in block_lower:

            severity = "medium"

        # Keyword-based severity improvements

        if any(
            keyword in block_lower
            for keyword in [
                "remote code execution",
                "arbitrary code execution"
            ]
        ):

            severity = "critical"

        elif any(
            keyword in block_lower
            for keyword in [
                "sql injection",
                "authentication bypass",
                "remote file inclusion"
            ]
        ):

            severity = "high"

        # -----------------------------------------------------
        # Deduplicate
        # -----------------------------------------------------

        dedup_key = (
            clean_host,
            script_name,
            block_text
        )

        if dedup_key in seen:
            continue

        seen.add(dedup_key)

        # -----------------------------------------------------
        # Clean description
        # -----------------------------------------------------

        clean_description = []

        for block_line in block_lines:

            cleaned = (
                block_line
                .replace("|_", "")
                .replace("|", "")
                .strip()
            )

            if cleaned:
                clean_description.append(cleaned)

        description = "\n".join(clean_description)

        # -----------------------------------------------------
        # Store ONE finding per script block
        # -----------------------------------------------------

        findings.append(

            format_standard_finding(

                tool="Nmap",

                target=target_url,

                vulnerability=script_name,

                severity=severity,

                description=description,

                evidence=f"Host: {clean_host}",

                reference=(
                    "https://nmap.org/nsedoc/scripts/"
                    f"{script_name}.html"
                )
            )
        )

    print(f"    [+] Nmap findings: {len(findings)}")

    return findings


# =====================================================================
# 6. SSLYZE WRAPPER
# =====================================================================
def run_sslyze_scan(target_url: str, clean_host: str) -> List[Dict[str, Any]]:
    findings = []

    print(f"[*] [6/7] Running SSLyze on {clean_host}...")

    stdout, err = safe_run_command(
        ["sslyze", "--json_out=-", f"{clean_host}:443"],
        timeout=None
    )

    if stdout and stdout.strip().startswith("{"):
        try:
            data = json.loads(stdout)
            server_scan = data.get("server_scan_results", [])

            if server_scan:
                scan_result = server_scan[0].get("scan_result", {})
                if scan_result is None:
                    print("[+] SSLyze: No TLS/SSL scan result for this HTTP target. Skipping.")
                    return []

                # -------------------------------
                # TLS 1.0
                # -------------------------------
                tls_1_0 = scan_result.get("tls_1_0_cipher_suites", {})
                tls_1_0_result = tls_1_0.get("result", {})

                if tls_1_0_result.get("is_tls_version_supported") is True:
                    findings.append(format_standard_finding(
                        tool="SSLyze",
                        target=f"https://{clean_host}",
                        vulnerability="TLS 1.0 Supported",
                        severity="medium",
                        description="The server supports the deprecated TLS 1.0 protocol.",
                        evidence=f"TLS 1.0 is supported by {clean_host}:443.",
                        reference="https://datatracker.ietf.org/doc/html/rfc8996"
                    ))

                # -------------------------------
                # TLS 1.1
                # -------------------------------
                tls_1_1 = scan_result.get("tls_1_1_cipher_suites", {})
                tls_1_1_result = tls_1_1.get("result", {})

                if tls_1_1_result.get("is_tls_version_supported") is True:
                    findings.append(format_standard_finding(
                        tool="SSLyze",
                        target=f"https://{clean_host}",
                        vulnerability="TLS 1.1 Supported",
                        severity="medium",
                        description="The server supports the deprecated TLS 1.1 protocol.",
                        evidence=f"TLS 1.1 is supported by {clean_host}:443.",
                        reference="https://datatracker.ietf.org/doc/html/rfc8996"
                    ))

                # -------------------------------
                # Weak CBC cipher suites
                # -------------------------------
                weak_ciphers = []

                for tls_version, tls_data in [
                    ("TLS 1.0", tls_1_0_result),
                    ("TLS 1.1", tls_1_1_result)
                ]:
                    for cipher in tls_data.get("accepted_cipher_suites", []):
                        cipher_info = cipher.get("cipher_suite", {})
                        cipher_name = cipher_info.get("name", "")

                        if "_CBC_" in cipher_name:
                            weak_ciphers.append(
                                f"{tls_version}: {cipher_name}"
                            )

                if weak_ciphers:
                    findings.append(format_standard_finding(
                        tool="SSLyze",
                        target=f"https://{clean_host}",
                        vulnerability="Weak CBC Cipher Suites",
                        severity="low",
                        description="The server accepts TLS cipher suites using CBC mode, which are considered weaker than modern AEAD cipher suites.",
                        evidence="; ".join(weak_ciphers),
                        reference="https://datatracker.ietf.org/doc/html/rfc8996"
                    ))

        except json.JSONDecodeError:
            print("    [!] SSLyze returned invalid JSON.")

    elif err:
        print(f"    [!] SSLyze: {err}")

    print(f"    [+] SSLyze findings: {len(findings)}")

    return findings


# =====================================================================
# 7. WAPITI WRAPPER
# =====================================================================
def run_wapiti_scan(target_url: str, clean_host: str) -> List[Dict[str, Any]]:

    findings = []
    seen_findings = set()

    # ---------------------------------------------------------
    # Output file
    # ---------------------------------------------------------

    output_file = os.path.join(
        TEMP_DIR,
        "wapiti_out.json"
    )

    # Remove old report if it exists
    if os.path.exists(output_file):
        os.remove(output_file)

    print(
        f"[*] [7/7] Running Wapiti on {target_url}..."
    )

    # ---------------------------------------------------------
    # Build Wapiti command
    # ---------------------------------------------------------

    command = [
        "wapiti",
        "-u", target_url,
        "-f", "json",
        "-o", output_file
    ]

    # ---------------------------------------------------------
    # Run Wapiti
    # ---------------------------------------------------------

    stdout, err = safe_run_command(
        command,
        timeout=None
    )

    # ---------------------------------------------------------
    # Check whether report was generated
    # ---------------------------------------------------------

    if not (
        os.path.exists(output_file)
        and os.path.getsize(output_file) > 0
    ):

        print(
            "    [!] Wapiti did not generate a valid JSON report."
        )

        if err:
            print(
                f"    [!] Wapiti stderr:\n{err}"
            )

        return findings

    # ---------------------------------------------------------
    # Wapiti severity mapping
    # ---------------------------------------------------------

    severity_map = {
        0: "info",
        1: "low",
        2: "medium",
        3: "high",
        4: "critical"
    }

    # ---------------------------------------------------------
    # Parse Wapiti JSON
    # ---------------------------------------------------------

    try:

        with open(
            output_file,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:

            data = json.load(f)

        vulnerabilities = data.get(
            "vulnerabilities",
            {}
        )

        # -----------------------------------------------------
        # Process vulnerability categories
        # -----------------------------------------------------

        for category, items in vulnerabilities.items():

            # Empty list means no vulnerability found
            if not items:
                continue

            # Safety check
            if not isinstance(items, list):
                continue

            # -------------------------------------------------
            # Process vulnerability entries
            # -------------------------------------------------

            for item in items:

                if not isinstance(item, dict):
                    continue

                # ---------------------------------------------
                # Get Wapiti severity level
                # ---------------------------------------------

                level = item.get("level", 0)

                try:
                    level = int(level)

                except (ValueError, TypeError):
                    level = 0

                severity = severity_map.get(
                    level,
                    "info"
                )

                # ---------------------------------------------
                # Get finding details
                # ---------------------------------------------

                path = item.get(
                    "path",
                    "/"
                )

                info = item.get(
                    "info",
                    f"Wapiti detected: {category}"
                )

                method = item.get(
                    "method",
                    ""
                )

                parameter = item.get(
                    "parameter",
                    ""
                )

                module = item.get(
                    "module",
                    ""
                )

                # -------------------------------------------------
                # Filter informational SSL cipher messages
                # -------------------------------------------------

                if category == "TLS/SSL misconfigurations":

                    info_lower = info.lower()

                    informational_ssl_patterns = [
                        "the following ciphers are acceptable for tlsv1.0",
                        "the following ciphers are acceptable for tlsv1.1",
                        "the following ciphers are acceptable for tlsv1.2",
                        "the following ciphers are acceptable for tlsv1.3",
                    ]

                    if any(
                        pattern in info_lower
                        for pattern in informational_ssl_patterns
                    ):
                        continue

                # -------------------------------------------------
                # Deduplicate findings
                # -------------------------------------------------

                dedup_key = (
                    category.lower(),
                    path,
                    info.lower(),
                    str(parameter)
                )

                if dedup_key in seen_findings:
                    continue

                seen_findings.add(
                    dedup_key
                )

                # -------------------------------------------------
                # Build evidence
                # -------------------------------------------------

                evidence_parts = [
                    f"Host: {clean_host}",
                    f"Path: {path}"
                ]

                if method:
                    evidence_parts.append(
                        f"Method: {method}"
                    )

                if parameter:
                    evidence_parts.append(
                        f"Parameter: {parameter}"
                    )

                if module:
                    evidence_parts.append(
                        f"Module: {module}"
                    )

                evidence = " | ".join(
                    evidence_parts
                )


                # -------------------------------------------------
                # Store standardized finding
                # -------------------------------------------------

                findings.append(

                    format_standard_finding(

                        tool="Wapiti",

                        target=target_url,

                        vulnerability=category,

                        severity=severity,

                        description=info,

                        evidence=evidence,

                        reference=(
                            "https://wapiti-scanner.github.io/"
                        )
                    )
                )

    # ---------------------------------------------------------
    # Error handling
    # ---------------------------------------------------------

    except json.JSONDecodeError as e:

        print(
            f"    [!] Failed to parse Wapiti JSON: {e}"
        )

    except Exception as e:

        print(
            f"    [!] Wapiti parser error: {e}"
        )

    # ---------------------------------------------------------
    # Cleanup
    # ---------------------------------------------------------

    finally:

        if os.path.exists(output_file):

            try:
                os.remove(output_file)

            except OSError:
                pass

    # ---------------------------------------------------------
    # Final result
    # ---------------------------------------------------------

    print(
        f"    [+] Wapiti captured "
        f"{len(findings)} normalized findings."
    )

    return findings


# =====================================================================
# MAIN PIPELINE
# =====================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cross-Platform Multi-Scanner Engine (7 Scanners)")
    parser.add_argument("url", nargs="?", help="Target URL (e.g. http://scanme.sh)")
    args = parser.parse_args()

    input_url = args.url or input("Enter target URL: ").strip()
    if not input_url:
        sys.exit(1)

    target_url, clean_host = parse_target(input_url)

    print(f"\n========================================================")
    print(f"🚀 STARTING MULTI-SCANNER ENGINE FOR: {target_url}")
    print(f"💻 Host Environment: {os.name} ({sys.platform})")
    print(f"========================================================\n")

    all_standardized_findings: List[Dict[str, Any]] = []
    all_standardized_findings.extend(run_nuclei_scan(target_url, clean_host))
    all_standardized_findings.extend(run_nikto_scan(target_url, clean_host))
    all_standardized_findings.extend(run_zap_scan(target_url))
    all_standardized_findings.extend(run_whatweb_scan(target_url, clean_host))
    all_standardized_findings.extend(run_nmap_vuln_scan(target_url, clean_host))
    all_standardized_findings.extend(run_sslyze_scan(target_url, clean_host))
    all_standardized_findings.extend(run_wapiti_scan(target_url, clean_host))

    output_path = "standardized_scan_results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_standardized_findings, f, indent=2)

    print(f"\n========================================================")
    print(f"✅ SCAN COMPLETE!")
    print(f"[+] Total raw standardized findings saved: {len(all_standardized_findings)}")
    print(f"[+] Output file written to: {os.path.abspath(output_path)}")
    print(f"========================================================\n")