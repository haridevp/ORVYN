"""
Generates targeted retrieval queries from a consolidated finding.
Multiple query variants outperform one blended query — covers definition,
remediation, and MITRE-style technique phrasing separately.
"""


def generate_queries(finding: dict) -> list[str]:
    vuln = finding.get("vulnerability", "").strip()
    cwe = finding.get("reference", "").strip()

    queries = [
        f"{vuln} vulnerability description and impact",
        f"{vuln} remediation and mitigation best practices",
        f"{vuln} attack technique exploitation",
    ]

    if cwe and cwe.upper().startswith("CWE"):
        queries.append(f"{cwe} common weakness definition")

    return queries


if __name__ == "__main__":
    sample = {
        "vulnerability": "SQL Injection",
        "reference": "CWE-89"
    }
    for q in generate_queries(sample):
        print(" -", q)