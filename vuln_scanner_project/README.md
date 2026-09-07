# Multi-Scanner Vulnerability Scanner Engine

This module provides a cross-platform vulnerability scanning engine that integrates multiple security scanners and normalizes their findings into a standardized JSON format.

## Supported Scanners

* Nuclei
* Nikto
* OWASP ZAP
* WhatWeb
* Nmap
* SSLyze
* Wapiti

## Build the Docker Image

From the project directory, run:

```bash
docker build -t vuln-scanner .
```

## Run the Scanner

Run the scanner against a target URL:

```bash
docker run --rm vuln-scanner python scanner_engine_2.py <TARGET_URL>
```

Example:

```bash
docker run --rm vuln-scanner python scanner_engine_2.py http://example.com
```

## Run with a Mounted Output Directory

To save the generated results to your local machine:

### Linux / Kali

```bash
docker run --rm -v "$(pwd):/app" vuln-scanner python scanner_engine_2.py <TARGET_URL>
```

### Windows PowerShell

```powershell
docker run --rm -v "${PWD}:/app" vuln-scanner python scanner_engine_2.py <TARGET_URL>
```

## Output

The scanner generates:

```text
standardized_scan_results.json
```

This file contains normalized findings collected from all supported scanners.
