import json
import uuid
import os
from database import get_collection

INITIAL_KNOWLEDGE = [
    # --- OWASP Top 10:2025 Definitions ---
    {
        "id": "owasp-a01-2025",
        "title": "OWASP A01:2025 - Broken Access Control",
        "content": "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, destruction of data, or performing a business function outside the user's limits. Includes IDOR, missing function-level access control, directory traversal, and CORS misconfiguration.",
        "reference": "https://owasp.org/Top10/2025/A01_Broken_Access_Control/"
    },
    {
        "id": "owasp-a02-2025",
        "title": "OWASP A02:2025 - Security Misconfiguration",
        "content": "Security misconfiguration involves unhardened default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, unnecessary services, and verbose error messages containing stack traces or sensitive architecture details.",
        "reference": "https://owasp.org/Top10/2025/A02_Security_Misconfiguration/"
    },
    {
        "id": "owasp-a03-2025",
        "title": "OWASP A03:2025 - Software Supply Chain Failures",
        "content": "Supply chain vulnerabilities arise when applications rely on outdated, vulnerable, or malicious third-party dependencies, unpinned libraries, compromised repositories, or unverified package builds. Regular software composition analysis (SCA) and SBOM tracking are required.",
        "reference": "https://owasp.org/Top10/2025/A03_Software_Supply_Chain_Failures/"
    },
    {
        "id": "owasp-a04-2025",
        "title": "OWASP A04:2025 - Cryptographic Failures",
        "content": "Cryptographic failures result in sensitive data exposure in transit or at rest. Common root causes include deprecated TLS protocols (TLS 1.0, TLS 1.1), weak cipher suites (RC4, DES), missing HTTPS redirection, hardcoded cryptographic keys, and improper certificate validation.",
        "reference": "https://owasp.org/Top10/2025/A04_Cryptographic_Failures/"
    },
    {
        "id": "owasp-a05-2025",
        "title": "OWASP A05:2025 - Injection",
        "content": "Injection flaws occur when untrusted user input is sent to an interpreter as part of a command or query. Covers SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, LDAP Injection, and ORM/NoSQL injection. Mitigated via parameterized queries, contextual encoding, and strict allowlists.",
        "reference": "https://owasp.org/Top10/2025/A05_Injection/"
    },
    {
        "id": "owasp-a06-2025",
        "title": "OWASP A06:2025 - Insecure Design",
        "content": "Insecure design represents missing or ineffective security controls at the architectural phase, such as lack of threat modeling, absence of rate-limiting on sensitive endpoints, business logic flaws, and clickjacking vulnerabilities due to missing frame protections.",
        "reference": "https://owasp.org/Top10/2025/A06_Insecure_Design/"
    },
    {
        "id": "owasp-a07-2025",
        "title": "OWASP A07:2025 - Authentication Failures",
        "content": "Authentication failures allow attackers to compromise passwords, keys, or session tokens, or exploit implementation flaws to assume identities. Includes credential stuffing, brute force attacks, missing MFA, session fixation, and weak session expiration rules.",
        "reference": "https://owasp.org/Top10/2025/A07_Authentication_Failures/"
    },
    {
        "id": "owasp-a08-2025",
        "title": "OWASP A08:2025 - Software and Data Integrity Failures",
        "content": "Integrity failures relate to code and infrastructure that do not protect against integrity violations. Covers insecure deserialization of untrusted payloads, unvalidated software updates, and unrestricted file uploads that permit web shells or malicious executables.",
        "reference": "https://owasp.org/Top10/2025/A08_Software_and_Data_Integrity_Failures/"
    },

    # --- CWE Top 25:2024 Definitions ---
    {
        "id": "cwe-89",
        "title": "CWE-89: SQL Injection",
        "content": "SQL Injection occurs when user-supplied data is included in a SQL query without proper sanitization or parameterization. Attackers can read, modify, or delete database tables, bypass authentication, and in some database configurations execute administrative commands. Mitigation: Use Prepared Statements (Parameterized Queries), Stored Procedures, and Object-Relational Mappers (ORMs).",
        "reference": "https://cwe.mitre.org/data/definitions/89.html"
    },
    {
        "id": "cwe-79",
        "title": "CWE-79: Cross-Site Scripting (XSS)",
        "content": "XSS vulnerabilities occur when an application includes untrusted data in a web page without proper validation or contextual escaping. Reflected, Stored, or DOM-based variants allow attackers to execute arbitrary JavaScript in the victim's browser session, stealing cookies and tokens. Mitigation: Context-aware output encoding, strict Content Security Policy (CSP), and HTTPOnly cookie flags.",
        "reference": "https://cwe.mitre.org/data/definitions/79.html"
    },
    {
        "id": "cwe-918",
        "title": "CWE-918: Server-Side Request Forgery (SSRF)",
        "content": "SSRF occurs when a web application fetches a remote resource without validating the user-supplied destination URL. Attackers force the server to initiate network connections to internal infrastructure, cloud metadata services (169.254.169.254), or local loopback services. Mitigation: Validate URLs against an allowlist, disable unsafe URI schemes (file://, dict://), and enforce egress network filtering.",
        "reference": "https://cwe.mitre.org/data/definitions/918.html"
    },
    {
        "id": "cwe-78",
        "title": "CWE-78: OS Command Injection",
        "content": "OS Command Injection occurs when an application executes host operating system commands using unsanitized user-supplied input. Attackers append shell metacharacters (; | &) to execute arbitrary commands with the privileges of the web application. Mitigation: Avoid shell invocation APIs, use parameterized subprocess execution with argv arrays, and validate against strict alphanumeric allowlists.",
        "reference": "https://cwe.mitre.org/data/definitions/78.html"
    },
    {
        "id": "cwe-22",
        "title": "CWE-22: Path Traversal / Arbitrary File Read",
        "content": "Path Traversal allows an attacker to access files and directories stored outside the intended web root by manipulating path references with dot-dot-slash (../) sequences. Exposes sensitive credentials, configuration files, and operating system assets. Mitigation: Canonicalize paths before validation, resolve against a fixed root directory, and reject inputs containing directory traversal characters.",
        "reference": "https://cwe.mitre.org/data/definitions/22.html"
    },
    {
        "id": "cwe-200",
        "title": "CWE-200: Exposure of Sensitive Information",
        "content": "Information exposure occurs when software unintentionally exposes sensitive system telemetry, internal server banners, environment configurations (.env), version numbers, or stack traces to unauthorized parties, assisting targeted exploitation. Mitigation: Disable verbose error modes, remove detailed server headers, and restrict access to configuration backups.",
        "reference": "https://cwe.mitre.org/data/definitions/200.html"
    },
    {
        "id": "cwe-352",
        "title": "CWE-352: Cross-Site Request Forgery (CSRF)",
        "content": "CSRF forces an authenticated victim browser to transmit forged requests to a vulnerable application, executing unwanted state-changing transactions. Mitigation: Cryptographic anti-CSRF tokens, SameSite=Strict/Lax cookie directives, and re-authentication for critical actions.",
        "reference": "https://cwe.mitre.org/data/definitions/352.html"
    },
    {
        "id": "cwe-502",
        "title": "CWE-502: Deserialization of Untrusted Data",
        "content": "Deserialization of untrusted data allows attackers to manipulate object state and execute arbitrary code via gadget chains during payload reconstruction. Mitigation: Avoid native language serialization (Java ObjectInputStream, Python pickle, PHP unserialize), use safe serialization formats like JSON, and enforce strict type allowlisting.",
        "reference": "https://cwe.mitre.org/data/definitions/502.html"
    },
    {
        "id": "cwe-326",
        "title": "CWE-326: Inadequate Encryption Strength (TLS/SSL Flaws)",
        "content": "Inadequate encryption strength involves using weak encryption algorithms, short keys, or deprecated protocol versions (TLS 1.0, TLS 1.1, SSLv3). Subject to cryptanalytic attacks like POODLE, BEAST, or passive traffic eavesdropping. Mitigation: Enforce TLS 1.2 and TLS 1.3 with forward-secret cipher suites (ECDHE-RSA-AES-GCM).",
        "reference": "https://cwe.mitre.org/data/definitions/326.html"
    },

    # --- Authoritative CVE Benchmarks & Remediation Patterns ---
    {
        "id": "cve-2023-38606",
        "title": "CVE-2023-38606: Web Application SQL Injection Vulnerability",
        "content": "SQL Injection vulnerability permitting remote attackers to craft HTTP parameters that alter backend SQL logic and extract data. Mitigation: Immediate code review to replace concatenated SQL strings with parameterized queries; deploy Web Application Firewall (WAF) query inspection rules.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-38606"
    },
    {
        "id": "cve-2021-44228",
        "title": "CVE-2021-44228: Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "content": "Remote Code Execution vulnerability in Apache Log4j2 JNDI features allowing unauthenticated attackers to execute arbitrary code via user-agent or request strings containing jndi:ldap lookups. Mitigation: Upgrade Log4j to version 2.17.1+ or set log4j2.formatMsgNoLookups=true.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    {
        "id": "cve-2021-41773",
        "title": "CVE-2021-41773: Apache HTTP Server Path Traversal and RCE",
        "content": "Path traversal flaw in Apache HTTP Server 2.4.49 where URL path normalization fails to resolve mapped directories properly, allowing access to files outside configured documents. Mitigation: Upgrade to Apache HTTP Server 2.4.51 or later; enforce default 'Require all denied' on root filesystem directories.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
    },
    {
        "id": "cve-2021-26855",
        "title": "CVE-2021-26855: Microsoft Exchange Server SSRF (ProxyLogon)",
        "content": "Server-Side Request Forgery vulnerability allowing unauthenticated remote attackers to send arbitrary HTTP requests and bypass authentication to access Exchange backend servers. Mitigation: Apply vendor security updates; enforce strict reverse proxy endpoint validation.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855"
    },
    {
        "id": "cve-2014-0160",
        "title": "CVE-2014-0160: OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)",
        "content": "Memory over-read in OpenSSL TLS heartbeat extension allowing remote attackers to read 64KB chunks of process memory containing private keys, passwords, and session tokens. Mitigation: Upgrade OpenSSL to 1.0.1g or later and revoke/reissue SSL/TLS certificates.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"
    },
    {
        "id": "cve-2024-3400",
        "title": "CVE-2024-3400: PAN-OS Command Injection Vulnerability",
        "content": "Command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software allowing unauthenticated attackers to execute arbitrary OS commands with root privileges. Mitigation: Upgrade PAN-OS to patched maintenance releases and enable Threat Prevention signatures.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"
    },
    {
        "id": "cve-general",
        "title": "General CVE Remediation Patterns",
        "content": "For specific CVEs, always consult the vendor's official advisory and apply the recommended patch or upgrade to a non-vulnerable version. If patching is not immediately possible, implement compensating controls such as WAF rules or network segmentation.",
        "reference": "https://nvd.nist.gov/"
    }
]

def seed_knowledge_base():
    collection = get_collection()
    
    ids = []
    documents = []
    metadatas = []
    
    for item in INITIAL_KNOWLEDGE:
        ids.append(item["id"])
        documents.append(f"{item['title']}\n\n{item['content']}")
        metadatas.append({"title": item["title"], "reference": item["reference"]})
        
    collection.upsert(
        documents=documents,
        metadatas=metadatas,
        ids=ids
    )
    return len(ids)

def ingest_custom_markdown_or_json(file_path: str):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File {file_path} not found.")
        
    collection = get_collection()
    
    if file_path.endswith('.json'):
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        ids = []
        documents = []
        metadatas = []
        
        for item in data:
            doc_id = item.get("id", str(uuid.uuid4()))
            title = item.get("title", "Custom Knowledge")
            content = item.get("content", "")
            reference = item.get("reference", "")
            
            ids.append(doc_id)
            documents.append(f"{title}\n\n{content}")
            metadatas.append({"title": title, "reference": reference})
            
        if ids:
            collection.upsert(documents=documents, metadatas=metadatas, ids=ids)
        return len(ids)
        
    elif file_path.endswith('.md'):
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        doc_id = str(uuid.uuid4())
        collection.upsert(
            documents=[content],
            metadatas=[{"title": os.path.basename(file_path), "reference": "Local Markdown File"}],
            ids=[doc_id]
        )
        return 1
    else:
        raise ValueError("Unsupported file format. Only .json and .md are supported.")
