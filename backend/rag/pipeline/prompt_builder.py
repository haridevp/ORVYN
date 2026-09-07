"""
Builds the analysis prompt combining the scanner finding with retrieved
security knowledge context.
"""


def build_prompt(finding: dict, context: str) -> str:
    return f"""You are a security analyst reviewing an automated scanner finding.
Use the retrieved knowledge below to inform your analysis — don't rely only on general knowledge.

FINDING:
Tool: {finding.get('tool')}
Target: {finding.get('target')}
Vulnerability: {finding.get('vulnerability')}
Severity (reported by scanner): {finding.get('severity')}
Description: {finding.get('description')}
Evidence: {finding.get('evidence')}

RETRIEVED KNOWLEDGE:
{context if context else "No relevant knowledge retrieved."}

Based on the finding and retrieved knowledge, respond with ONLY a JSON object
(no markdown, no extra text) with these exact keys:
{{
  "explanation": "clear explanation of the vulnerability in context of this finding",
  "severity": "Critical | High | Medium | Low",
  "confidence": <integer 0-100, confidence this is a true positive>,
  "false_positive_likelihood": "Low | Medium | High",
  "remediation": "concrete remediation steps"
}}
"""