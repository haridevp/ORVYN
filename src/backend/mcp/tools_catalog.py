"""HexStrike MCP Curated Tools Catalog.

Comprehensive registry of 68 curated security tools across 8 key operational categories:
1. Reconnaissance & OSINT (12 tools)
2. Content Discovery & Spidering (8 tools)
3. Web Vulnerability Scanning (14 tools)
4. Network, SSL/TLS & Infrastructure (8 tools)
5. Directory & Parameter Fuzzing (6 tools)
6. Injection & Exploitation Testing (7 tools)
7. Cloud, Secrets & Configuration Audit (8 tools)
8. Authentication & Credential Auditing (5 tools)
"""

from typing import Any
from pydantic import BaseModel, Field


class MCPToolDefinition(BaseModel):
    name: str
    display_name: str
    category: str
    description: str
    binary: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    default_args: list[str] = Field(default_factory=list)


HEXSTRIKE_TOOLS_CATALOG: list[MCPToolDefinition] = [
    # -------------------------------------------------------------
    # Category 1: Reconnaissance & OSINT (12 tools)
    # -------------------------------------------------------------
    MCPToolDefinition(
        name="nmap",
        display_name="Nmap Network Mapper",
        category="Reconnaissance & OSINT",
        description="Comprehensive network exploration, port scanning, service versioning, and NSE vulnerability scanning.",
        binary="nmap",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target hostname or IP address"},
                "ports": {"type": "string", "description": "Port range (e.g. '22,80,443' or '1-1000')"},
                "scripts": {"type": "string", "description": "NSE script suite (e.g. 'vulners,vuln,default')"},
            },
            "required": ["target"],
        },
        default_args=["-sV", "-Pn", "-T4", "--script=vulners,vuln"],
    ),
    MCPToolDefinition(
        name="masscan",
        display_name="Masscan High-Speed Port Scanner",
        category="Reconnaissance & OSINT",
        description="Ultra-high-speed TCP port scanner capable of scanning entire networks in seconds.",
        binary="masscan",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target subnet or IP range"},
                "ports": {"type": "string", "description": "Target port specification, e.g. '0-65535'"},
                "rate": {"type": "integer", "description": "Packet rate per second (default: 1000)"},
            },
            "required": ["target"],
        },
        default_args=["--rate=1000"],
    ),
    MCPToolDefinition(
        name="rustscan",
        display_name="RustScan Modern Port Scanner",
        category="Reconnaissance & OSINT",
        description="Fast port scanner built in Rust that pairs rapid socket discovery with automated Nmap pipe.",
        binary="rustscan",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target hostname or IP"},
            },
            "required": ["target"],
        },
        default_args=["-a"],
    ),
    MCPToolDefinition(
        name="subfinder",
        display_name="Subfinder Subdomain Discovery",
        category="Reconnaissance & OSINT",
        description="Passive subdomain discovery tool that discovers valid subdomains for websites using passive online sources.",
        binary="subfinder",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Base target domain (e.g. example.com)"},
            },
            "required": ["domain"],
        },
        default_args=["-silent", "-all"],
    ),
    MCPToolDefinition(
        name="amass",
        display_name="OWASP Amass Attack Surface Mapper",
        category="Reconnaissance & OSINT",
        description="In-depth attack surface mapping and asset discovery using open source information gathering and active recon.",
        binary="amass",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain name to map"},
            },
            "required": ["domain"],
        },
        default_args=["enum", "-passive"],
    ),
    MCPToolDefinition(
        name="assetfinder",
        display_name="Assetfinder Domain Scout",
        category="Reconnaissance & OSINT",
        description="Rapid subdomain discovery via crt.sh, CertSpotter, and threat intelligence feeds.",
        binary="assetfinder",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target root domain"},
            },
            "required": ["domain"],
        },
        default_args=["--subs-only"],
    ),
    MCPToolDefinition(
        name="findomain",
        display_name="Findomain Cross-Platform Subdomain Hunter",
        category="Reconnaissance & OSINT",
        description="High-speed subdomain enumeration utilizing multi-threaded Certificate Transparency lookups.",
        binary="findomain",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target domain"},
            },
            "required": ["target"],
        },
        default_args=["--quiet"],
    ),
    MCPToolDefinition(
        name="shuffledns",
        display_name="ShuffleDNS Resolver & Brute-Forcer",
        category="Reconnaissance & OSINT",
        description="High-speed DNS resolver and bruteforcing tool wrapper around massdns for active subdomain discovery.",
        binary="shuffledns",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
            },
            "required": ["domain"],
        },
        default_args=["-mode", "resolve"],
    ),
    MCPToolDefinition(
        name="dnsx",
        display_name="DNSx Multi-Purpose DNS Toolkit",
        category="Reconnaissance & OSINT",
        description="Fast and multi-purpose DNS toolkit allow to run multiple DNS queries of your choice with DNS wildcard filtering.",
        binary="dnsx",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain or file with domain list"},
            },
            "required": ["domain"],
        },
        default_args=["-silent", "-a", "-cname", "-resp"],
    ),
    MCPToolDefinition(
        name="httpx",
        display_name="HTTPx Probing & Service Fingerprinter",
        category="Reconnaissance & OSINT",
        description="Fast and multi-purpose HTTP toolkit that allows running multiple probes to inspect status, title, tech, and TLS.",
        binary="httpx",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or URL"},
            },
            "required": ["target"],
        },
        default_args=["-silent", "-status-code", "-title", "-tech-detect", "-follow-redirects"],
    ),
    MCPToolDefinition(
        name="naabu",
        display_name="Naabu SYN/CONNECT Port Scanner",
        category="Reconnaissance & OSINT",
        description="Fast SYN and connect port scanner written in Go focused on reliability and simplicity.",
        binary="naabu",
        parameters={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target host or IP"},
            },
            "required": ["host"],
        },
        default_args=["-top-ports", "1000", "-silent"],
    ),
    MCPToolDefinition(
        name="katana",
        display_name="Katana Next-Gen Web Crawler",
        category="Reconnaissance & OSINT",
        description="Next-generation web crawler that automates endpoint discovery, headless DOM parsing, and JavaScript scraping.",
        binary="katana",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target seed URL"},
                "depth": {"type": "integer", "description": "Crawling depth (default: 3)"},
            },
            "required": ["url"],
        },
        default_args=["-silent", "-d", "3", "-jc"],
    ),

    # -------------------------------------------------------------
    # Category 2: Content Discovery & Spidering (8 tools)
    # -------------------------------------------------------------
    MCPToolDefinition(
        name="gau",
        display_name="GetAllURLs (GAU)",
        category="Content Discovery & Spidering",
        description="Fetches known URLs from AlienVault Open Threat Exchange, Wayback Machine, and Common Crawl.",
        binary="gau",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
            },
            "required": ["domain"],
        },
        default_args=["--subs"],
    ),
    MCPToolDefinition(
        name="waybackurls",
        display_name="WaybackURLs Archive Harvester",
        category="Content Discovery & Spidering",
        description="Fetches all URLs that the Wayback Machine has documented for a given domain.",
        binary="waybackurls",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
            },
            "required": ["domain"],
        },
        default_args=[],
    ),
    MCPToolDefinition(
        name="hakrawler",
        display_name="Hakrawler Fast Web Crawler",
        category="Content Discovery & Spidering",
        description="Fast Go web crawler designed for gathering endpoints, subdomains, and assets from websites.",
        binary="hakrawler",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
            },
            "required": ["url"],
        },
        default_args=["-depth", "2", "-plain"],
    ),
    MCPToolDefinition(
        name="paramspider",
        display_name="ParamSpider Parameter Miner",
        category="Content Discovery & Spidering",
        description="Extracts historical query parameters from web archives to uncover IDOR, SSRF, and SQLi vector endpoints.",
        binary="paramspider",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain"},
            },
            "required": ["domain"],
        },
        default_args=["--domain"],
    ),
    MCPToolDefinition(
        name="arjun",
        display_name="Arjun HTTP Parameter Discovery",
        category="Content Discovery & Spidering",
        description="Discovers hidden query, POST, and JSON parameters using heuristic bruteforcing.",
        binary="arjun",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL endpoint"},
            },
            "required": ["url"],
        },
        default_args=["-u"],
    ),
    MCPToolDefinition(
        name="crawley",
        display_name="Crawley Fast CLI Crawler",
        category="Content Discovery & Spidering",
        description="Unix-like web crawler written in Go focused on streaming stdout pipelines.",
        binary="crawley",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Base URL to crawl"},
            },
            "required": ["url"],
        },
        default_args=["-depth", "2"],
    ),
    MCPToolDefinition(
        name="gospider",
        display_name="GoSpider Fast Web Spider",
        category="Content Discovery & Spidering",
        description="Fast web spider written in Go with support for subdomains, sitemaps, robots.txt, and link extraction.",
        binary="gospider",
        parameters={
            "type": "object",
            "properties": {
                "site": {"type": "string", "description": "Target site URL"},
            },
            "required": ["site"],
        },
        default_args=["-s", "--js", "-t", "10"],
    ),
    MCPToolDefinition(
        name="cariddi",
        display_name="Cariddi Endpoint & Secret Harvester",
        category="Content Discovery & Spidering",
        description="Crawls websites looking for endpoints, secrets, API keys, file extensions, and parameters.",
        binary="cariddi",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
            },
            "required": ["url"],
        },
        default_args=["-ext", "2"],
    ),

    # -------------------------------------------------------------
    # Category 3: Web Vulnerability Scanning (14 tools)
    # -------------------------------------------------------------
    MCPToolDefinition(
        name="nuclei",
        display_name="Nuclei Vulnerability Scanner",
        category="Web Vulnerability Scanning",
        description="Fast and customizable vulnerability scanner based on community-powered YAML templates.",
        binary="nuclei",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or hostname"},
                "tags": {"type": "string", "description": "Template tags (e.g. 'cve,misconfig,exposure')"},
            },
            "required": ["target"],
        },
        default_args=["-j", "-duc"],
    ),
    MCPToolDefinition(
        name="nikto",
        display_name="Nikto Web Server Scanner",
        category="Web Vulnerability Scanning",
        description="Open source web server scanner that tests for dangerous files, outdated program versions, and server misconfigurations.",
        binary="nikto",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or URL"},
            },
            "required": ["target"],
        },
        default_args=["-Tuning", "123bde", "-nointeractive"],
    ),
    MCPToolDefinition(
        name="whatweb",
        display_name="WhatWeb Next-Gen Web Scanner",
        category="Web Vulnerability Scanning",
        description="Identifies websites, CMSs, blogging platforms, JavaScript libraries, web servers, and embedded devices.",
        binary="whatweb",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or IP"},
            },
            "required": ["target"],
        },
        default_args=["--color=never", "-a", "3", "--log-json"],
    ),
    MCPToolDefinition(
        name="wapiti",
        display_name="Wapiti Web Application Vulnerability Scanner",
        category="Web Vulnerability Scanning",
        description="Audits web applications by injecting payloads and inspecting responses for XSS, SQLi, SSRF, XXE, and LFI.",
        binary="wapiti",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target base URL"},
            },
            "required": ["target"],
        },
        default_args=["-u", "-f", "json", "-m", "xss,sql,exec,file,ssrf"],
    ),
    MCPToolDefinition(
        name="dalfox",
        display_name="DalFox XSS Scanner & Analyzer",
        category="Web Vulnerability Scanning",
        description="Powerful parameter analysis and XSS scanner with DOM parser and reflection testing.",
        binary="dalfox",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL to test for XSS"},
            },
            "required": ["url"],
        },
        default_args=["url", "--silence"],
    ),
    MCPToolDefinition(
        name="crlfuzz",
        display_name="CRLFuzz CRLF Injection Scanner",
        category="Web Vulnerability Scanning",
        description="Fast tool to scan CRLF vulnerabilities written in Go.",
        binary="crlfuzz",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
            },
            "required": ["url"],
        },
        default_args=["-u", "-s"],
    ),
    MCPToolDefinition(
        name="jaeles",
        display_name="Jaeles Automated Web Testing Suite",
        category="Web Vulnerability Scanning",
        description="Automated Web Application Security Testing tool with signature-based logic.",
        binary="jaeles",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
            },
            "required": ["url"],
        },
        default_args=["scan", "-u"],
    ),
    MCPToolDefinition(
        name="xray",
        display_name="Xray Security Scanner",
        category="Web Vulnerability Scanning",
        description="High-performance web security vulnerability scanner for SQLi, XSS, SSRF, and command execution.",
        binary="xray",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
            },
            "required": ["target"],
        },
        default_args=["webscan", "--url"],
    ),
    MCPToolDefinition(
        name="wpscan",
        display_name="WPScan WordPress Vulnerability Scanner",
        category="Web Vulnerability Scanning",
        description="Black box WordPress vulnerability scanner for themes, plugins, and core version vulnerabilities.",
        binary="wpscan",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "WordPress site URL"},
            },
            "required": ["url"],
        },
        default_args=["--url", "--enumerate", "vp,vt,u", "--no-banner"],
    ),
    MCPToolDefinition(
        name="droopescan",
        display_name="Droopescan CMS Scanner",
        category="Web Vulnerability Scanning",
        description="Plugin-based scanner for Drupal, SilverStripe, WordPress, and Joomla.",
        binary="droopescan",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
            },
            "required": ["url"],
        },
        default_args=["scan", "drupal", "-u"],
    ),
    MCPToolDefinition(
        name="joomscan",
        display_name="OWASP JoomScan Joomla Scanner",
        category="Web Vulnerability Scanning",
        description="OWASP Joomla Vulnerability Scanner detects file inclusion, SQL injection, and command execution in Joomla.",
        binary="joomscan",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target Joomla URL"},
            },
            "required": ["url"],
        },
        default_args=["-u"],
    ),
    MCPToolDefinition(
        name="cmseek",
        display_name="CMSeek Deep CMS Detection Suite",
        category="Web Vulnerability Scanning",
        description="Detects over 180 CMSs, scans for version disclosures, and identifies known exploit modules.",
        binary="cmseek",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
            },
            "required": ["url"],
        },
        default_args=["-u", "--batch"],
    ),
    MCPToolDefinition(
        name="graphql-cop",
        display_name="GraphQL Cop Security Auditor",
        category="Web Vulnerability Scanning",
        description="Security audit tool for GraphQL endpoints to detect introspection, field duplication, and batch attacks.",
        binary="graphql-cop",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "GraphQL endpoint URL"},
            },
            "required": ["target"],
        },
        default_args=["-t"],
    ),
    MCPToolDefinition(
        name="kiterunner",
        display_name="Kiterunner API Content Discovery",
        category="Web Vulnerability Scanning",
        description="Context-aware API content discovery tool designed to map REST, OpenAPI, and Swagger endpoints.",
        binary="kr",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target API host or base URL"},
            },
            "required": ["target"],
        },
        default_args=["scan"],
    ),

    # -------------------------------------------------------------
    # Category 4: Network, SSL/TLS & Infrastructure (8 tools)
    # -------------------------------------------------------------
    MCPToolDefinition(
        name="sslyze",
        display_name="SSLyze SSL/TLS Configuration Scanner",
        category="Network, SSL/TLS & Infrastructure",
        description="Fast and powerful SSL/TLS scanning library for protocol support, weak ciphers, and certificate validation.",
        binary="sslyze",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target hostname:port"},
            },
            "required": ["target"],
        },
        default_args=["--json_out=-"],
    ),
    MCPToolDefinition(
        name="testssl",
        display_name="TestSSL Command Line Suite",
        category="Network, SSL/TLS & Infrastructure",
        description="Checks server SSL/TLS ciphers, protocol flaws (Heartbleed, POODLE, ROBOT, SWEET32), and certificate chains.",
        binary="testssl.sh",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or hostname:port"},
            },
            "required": ["target"],
        },
        default_args=["--quiet", "--fast"],
    ),
    MCPToolDefinition(
        name="snmpwalk",
        display_name="SNMPwalk MIB Query Engine",
        category="Network, SSL/TLS & Infrastructure",
        description="Queries network devices via SNMP using GETNEXT requests to extract configuration and interface details.",
        binary="snmpwalk",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host IP"},
                "community": {"type": "string", "description": "SNMP community string (default: public)"},
            },
            "required": ["target"],
        },
        default_args=["-v2c", "-c", "public"],
    ),
    MCPToolDefinition(
        name="enum4linux",
        display_name="Enum4linux SMB/Samba Enumerator",
        category="Network, SSL/TLS & Infrastructure",
        description="Enumerates Windows and Samba systems for user lists, share enumeration, and password policies.",
        binary="enum4linux",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target Windows/Samba IP"},
            },
            "required": ["target"],
        },
        default_args=["-a"],
    ),
    MCPToolDefinition(
        name="smbclient",
        display_name="SMBClient Share Auditor",
        category="Network, SSL/TLS & Infrastructure",
        description="Interacts with SMB shares to identify anonymous access, null sessions, and exposed confidential files.",
        binary="smbclient",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host IP"},
            },
            "required": ["target"],
        },
        default_args=["-L", "-N"],
    ),
    MCPToolDefinition(
        name="nbtscan",
        display_name="NbtScan NetBIOS Name Scanner",
        category="Network, SSL/TLS & Infrastructure",
        description="Scans IP networks for NetBIOS name information to identify domain controllers, computers, and user names.",
        binary="nbtscan",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or subnet range"},
            },
            "required": ["target"],
        },
        default_args=["-r"],
    ),
    MCPToolDefinition(
        name="onesixtyone",
        display_name="OneSixtyOne SNMP Scanner",
        category="Network, SSL/TLS & Infrastructure",
        description="High-speed SNMP scanner capable of testing thousands of hosts for default community strings.",
        binary="onesixtyone",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or IP"},
            },
            "required": ["target"],
        },
        default_args=["-c", "public"],
    ),
    MCPToolDefinition(
        name="responder",
        display_name="Responder LLMNR/NBT-NS Auditor",
        category="Network, SSL/TLS & Infrastructure",
        description="Audits local subnet poisoning vulnerabilities across LLMNR, NBT-NS, and MDNS protocols.",
        binary="responder",
        parameters={
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Network interface to monitor (e.g. eth0)"},
            },
            "required": ["interface"],
        },
        default_args=["-A"],
    ),

    # -------------------------------------------------------------
    # Category 5: Directory & Parameter Fuzzing (6 tools)
    # -------------------------------------------------------------
    MCPToolDefinition(
        name="ffuf",
        display_name="FFuF Fast Web Fuzzer",
        category="Directory & Parameter Fuzzing",
        description="Fast web fuzzer written in Go for discovering hidden directories, files, virtual hosts, and API endpoints.",
        binary="ffuf",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with FUZZ keyword (e.g. https://target/FUZZ)"},
            },
            "required": ["url"],
        },
        default_args=["-s", "-mc", "200,204,301,302,307,401,403"],
    ),
    MCPToolDefinition(
        name="gobuster",
        display_name="Gobuster Directory & VHost Buster",
        category="Directory & Parameter Fuzzing",
        description="Directory, file, DNS, and vhost busting tool written in Go.",
        binary="gobuster",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target base URL"},
            },
            "required": ["url"],
        },
        default_args=["dir", "-q"],
    ),
    MCPToolDefinition(
        name="dirsearch",
        display_name="Dirsearch Advanced Web Path Scanner",
        category="Directory & Parameter Fuzzing",
        description="Advanced web path brute-forcer that identifies sensitive backup files, admin panels, and API endpoints.",
        binary="dirsearch",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target base URL"},
            },
            "required": ["url"],
        },
        default_args=["-u", "--format=json", "-q"],
    ),
    MCPToolDefinition(
        name="feroxbuster",
        display_name="Feroxbuster Recursive Content Discovery",
        category="Directory & Parameter Fuzzing",
        description="Fast, simple, recursive content discovery tool written in Rust that discovers deep file trees.",
        binary="feroxbuster",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target base URL"},
            },
            "required": ["url"],
        },
        default_args=["-u", "--silent"],
    ),
    MCPToolDefinition(
        name="wfuzz",
        display_name="WFuzz Web Application Fuzzer",
        category="Directory & Parameter Fuzzing",
        description="Modular web application fuzzer for finding vulnerabilities, parameters, and authentication bypasses.",
        binary="wfuzz",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL containing FUZZ keyword"},
            },
            "required": ["url"],
        },
        default_args=["--hc", "404"],
    ),
    MCPToolDefinition(
        name="vport",
        display_name="VHost Port & Virtual Host Scanner",
        category="Directory & Parameter Fuzzing",
        description="Fuzzes Host headers to discover internal virtual hosts and reverse proxy routing misconfigurations.",
        binary="ffuf",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
            },
            "required": ["url"],
        },
        default_args=["-H", "Host: FUZZ"],
    ),

    # -------------------------------------------------------------
    # Category 6: Injection & Exploitation Testing (7 tools)
    # -------------------------------------------------------------
    MCPToolDefinition(
        name="sqlmap",
        display_name="SQLMap Automatic SQL Injection Suite",
        category="Injection & Exploitation Testing",
        description="Automated SQL injection and database takeover tool detecting boolean, error, time, and stacked injection.",
        binary="sqlmap",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with injectable parameters"},
            },
            "required": ["url"],
        },
        default_args=["--batch", "--random-agent", "--level=1", "--risk=1"],
    ),
    MCPToolDefinition(
        name="ghauri",
        display_name="Ghauri Advanced SQL Injection Detector",
        category="Injection & Exploitation Testing",
        description="Lightweight and advanced SQL injection detection tool for high-concurrency environments.",
        binary="ghauri",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
            },
            "required": ["url"],
        },
        default_args=["--batch"],
    ),
    MCPToolDefinition(
        name="nosqlmap",
        display_name="NoSQLMap MongoDB & NoSQL Auditor",
        category="Injection & Exploitation Testing",
        description="Automated penetration testing tool designed to audit MongoDB and NoSQL web applications.",
        binary="nosqlmap",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target web application or MongoDB host"},
            },
            "required": ["target"],
        },
        default_args=[],
    ),
    MCPToolDefinition(
        name="commix",
        display_name="Commix Automated Command Injection Suite",
        category="Injection & Exploitation Testing",
        description="Automated tool designed to detect and exploit command injection and blind OS injection vulnerabilities.",
        binary="commix",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with test parameters"},
            },
            "required": ["url"],
        },
        default_args=["--batch"],
    ),
    MCPToolDefinition(
        name="tplmap",
        display_name="Tplmap Server-Side Template Injection Engine",
        category="Injection & Exploitation Testing",
        description="Detects and exploits Server-Side Template Injection (SSTI) across Jinja2, Twig, Velocity, and Mako.",
        binary="tplmap",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with potential template parameter"},
            },
            "required": ["url"],
        },
        default_args=["-u"],
    ),
    MCPToolDefinition(
        name="xsser",
        display_name="XSSer Cross-Site Scripting Framework",
        category="Injection & Exploitation Testing",
        description="Automatic framework to detect, exploit, and report XSS vulnerabilities in web-based applications.",
        binary="xsser",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
            },
            "required": ["url"],
        },
        default_args=["-u"],
    ),
    MCPToolDefinition(
        name="jwt_tool",
        display_name="JWT Tool Token Auditor",
        category="Injection & Exploitation Testing",
        description="Toolkit for validating, forging, scanning, and cracking JSON Web Tokens (JWTs).",
        binary="jwt_tool",
        parameters={
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "JWT string to inspect and test"},
            },
            "required": ["token"],
        },
        default_args=["-M", "at"],
    ),

    # -------------------------------------------------------------
    # Category 7: Cloud, Secrets & Configuration Audit (8 tools)
    # -------------------------------------------------------------
    MCPToolDefinition(
        name="trufflehog",
        display_name="TruffleHog High-Entropy Secret Scanner",
        category="Cloud, Secrets & Configuration Audit",
        description="Searches through git repositories and websites for high entropy strings, credentials, and API keys.",
        binary="trufflehog",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or git repository"},
            },
            "required": ["target"],
        },
        default_args=[],
    ),
    MCPToolDefinition(
        name="gitleaks",
        display_name="Gitleaks Hardcoded Secret Detector",
        category="Cloud, Secrets & Configuration Audit",
        description="Fast secret scanner focused on detecting hardcoded secrets, AWS keys, Slack tokens, and private keys.",
        binary="gitleaks",
        parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory or repository to audit"},
            },
            "required": ["path"],
        },
        default_args=["dir", "--no-git"],
    ),
    MCPToolDefinition(
        name="gitrob",
        display_name="Gitrob Organization Reconnaissance",
        category="Cloud, Secrets & Configuration Audit",
        description="Reconnaissance tool for GitHub organizations to help find sensitive files pushed to public repos.",
        binary="gitrob",
        parameters={
            "type": "object",
            "properties": {
                "org": {"type": "string", "description": "Target GitHub organization name"},
            },
            "required": ["org"],
        },
        default_args=[],
    ),
    MCPToolDefinition(
        name="prowler",
        display_name="Prowler Multi-Cloud Security Auditing",
        category="Cloud, Secrets & Configuration Audit",
        description="Open source security tool to perform AWS, Azure, and GCP security best practices assessments and CIS compliance.",
        binary="prowler",
        parameters={
            "type": "object",
            "properties": {
                "provider": {"type": "string", "description": "Cloud provider ('aws', 'azure', or 'gcp')"},
            },
            "required": ["provider"],
        },
        default_args=[],
    ),
    MCPToolDefinition(
        name="scoutsuite",
        display_name="Scout Suite Multi-Cloud Auditor",
        category="Cloud, Secrets & Configuration Audit",
        description="Open source multi-cloud security-auditing tool assessing cloud posture against security baselines.",
        binary="scout",
        parameters={
            "type": "object",
            "properties": {
                "provider": {"type": "string", "description": "Target cloud platform"},
            },
            "required": ["provider"],
        },
        default_args=[],
    ),
    MCPToolDefinition(
        name="checkov",
        display_name="Checkov Infrastructure-as-Code Scanner",
        category="Cloud, Secrets & Configuration Audit",
        description="Static code analysis tool for infrastructure-as-code to prevent cloud misconfigurations before deployment.",
        binary="checkov",
        parameters={
            "type": "object",
            "properties": {
                "directory": {"type": "string", "description": "Path to Terraform/Kubernetes manifests"},
            },
            "required": ["directory"],
        },
        default_args=["-d"],
    ),
    MCPToolDefinition(
        name="cloudflair",
        display_name="Cloudflair Origin IP Discovery",
        category="Cloud, Secrets & Configuration Audit",
        description="Uncovers origin IP addresses of web servers hidden behind Cloudflare CDN reverse proxies.",
        binary="cloudflair",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target domain hidden behind Cloudflare"},
            },
            "required": ["domain"],
        },
        default_args=[],
    ),
    MCPToolDefinition(
        name="s3scanner",
        display_name="S3Scanner Bucket Auditor",
        category="Cloud, Secrets & Configuration Audit",
        description="Scans for open, world-readable AWS S3 buckets and audits bucket ACLs and permissions.",
        binary="s3scanner",
        parameters={
            "type": "object",
            "properties": {
                "bucket": {"type": "string", "description": "Target bucket name or domain"},
            },
            "required": ["bucket"],
        },
        default_args=["scan"],
    ),

    # -------------------------------------------------------------
    # Category 8: Authentication & Credential Auditing (5 tools)
    # -------------------------------------------------------------
    MCPToolDefinition(
        name="hydra",
        display_name="THC-Hydra Network Login Auditor",
        category="Authentication & Credential Auditing",
        description="Fast network logon cracker supporting SSH, FTP, HTTP-POST, RDP, SMB, and 50+ protocols.",
        binary="hydra",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host IP or domain"},
                "service": {"type": "string", "description": "Service name (e.g. 'ssh', 'ftp', 'http-post-form')"},
            },
            "required": ["target", "service"],
        },
        default_args=["-I", "-t", "4"],
    ),
    MCPToolDefinition(
        name="medusa",
        display_name="Medusa Parallel Login Auditor",
        category="Authentication & Credential Auditing",
        description="Speedy, parallel, and modular login brute-forcer for auditing weak user credentials.",
        binary="medusa",
        parameters={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target host"},
                "module": {"type": "string", "description": "Target protocol module"},
            },
            "required": ["host", "module"],
        },
        default_args=["-M"],
    ),
    MCPToolDefinition(
        name="crackmapexec",
        display_name="CrackMapExec Active Directory Pentesting Suite",
        category="Authentication & Credential Auditing",
        description="Swiss army knife for pentesting Active Directory networks, SMB shares, and credential dumping.",
        binary="crackmapexec",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or subnet"},
                "protocol": {"type": "string", "description": "Protocol ('smb', 'winrm', 'ldap')"},
            },
            "required": ["target"],
        },
        default_args=["smb"],
    ),
    MCPToolDefinition(
        name="kerbrute",
        display_name="Kerbrute Active Directory Kerberos Auditor",
        category="Authentication & Credential Auditing",
        description="Tool to quickly bruteforce and enumerate valid Active Directory accounts via Kerberos Pre-Authentication.",
        binary="kerbrute",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Target AD domain"},
            },
            "required": ["domain"],
        },
        default_args=["userenum"],
    ),
    MCPToolDefinition(
        name="evil-winrm",
        display_name="Evil-WinRM Windows Remote Auditor",
        category="Authentication & Credential Auditing",
        description="WinRM administration and audit shell for hacking Windows and Active Directory endpoints.",
        binary="evil-winrm",
        parameters={
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Target Windows IP"},
            },
            "required": ["ip"],
        },
        default_args=["-i"],
    ),
]
