import json
import uuid
import os
from database import get_collection

INITIAL_KNOWLEDGE = [
    {
        "id": "cwe-89",
        "title": "CWE-89: SQL Injection",
        "content": "SQL Injection occurs when user-supplied data is included in a SQL query without proper sanitization or parameterization. Mitigation: Use Prepared Statements (Parameterized Queries), Stored Procedures, or ORMs. Validate input.",
        "reference": "https://cwe.mitre.org/data/definitions/89.html"
    },
    {
        "id": "cwe-79",
        "title": "CWE-79: Cross-Site Scripting (XSS)",
        "content": "XSS vulnerabilities occur when an application includes untrusted data in a web page without proper validation or escaping. It can be Stored, Reflected, or DOM-based. Mitigation: Use context-aware output encoding, sanitize input, implement Content Security Policy (CSP).",
        "reference": "https://cwe.mitre.org/data/definitions/79.html"
    },
    {
        "id": "cwe-918",
        "title": "CWE-918: Server-Side Request Forgery (SSRF)",
        "content": "SSRF occurs when a web application is fetching a remote resource without validating the user-supplied URL. Mitigation: Validate inputs, use an allowlist of permitted domains, disable unused URL schemas (like file://, dict://), and enforce network segmentation.",
        "reference": "https://cwe.mitre.org/data/definitions/918.html"
    },
    {
        "id": "cwe-78",
        "title": "CWE-78: OS Command Injection",
        "content": "OS Command Injection occurs when an application executes OS commands with user-supplied input without proper sanitization. Mitigation: Avoid calling OS commands directly. If necessary, strictly validate input against an allowlist and use safe APIs that do not spawn a shell.",
        "reference": "https://cwe.mitre.org/data/definitions/78.html"
    },
    {
        "id": "cwe-22",
        "title": "CWE-22: Path Traversal / LFI",
        "content": "Path Traversal allows an attacker to access files and directories that are stored outside the web root folder. Mitigation: Validate input against an allowlist, use absolute paths for resolution, and restrict file access to specific directories.",
        "reference": "https://cwe.mitre.org/data/definitions/22.html"
    },
    {
        "id": "cwe-287",
        "title": "CWE-287: Improper Authentication",
        "content": "Improper Authentication means the software does not correctly prove that a user is who they claim to be. Mitigation: Implement robust authentication mechanisms (e.g., MFA), use secure session management, and securely store credentials (hashing with salt).",
        "reference": "https://cwe.mitre.org/data/definitions/287.html"
    },
    {
        "id": "cwe-352",
        "title": "CWE-352: Cross-Site Request Forgery (CSRF)",
        "content": "CSRF forces an end user to execute unwanted actions on a web application in which they are currently authenticated. Mitigation: Use anti-CSRF tokens, check the Referer/Origin headers, and use SameSite cookie attributes.",
        "reference": "https://cwe.mitre.org/data/definitions/352.html"
    },
    {
        "id": "cwe-502",
        "title": "CWE-502: Deserialization of Untrusted Data",
        "content": "Deserialization of untrusted data can lead to remote code execution (RCE) or denial of service (DoS). Mitigation: Do not deserialize untrusted data. Use safe serialization formats like JSON. If native serialization must be used, implement integrity checks and strict type constraints.",
        "reference": "https://cwe.mitre.org/data/definitions/502.html"
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
