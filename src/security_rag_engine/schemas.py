from pydantic import BaseModel, Field
from typing import Optional, List, Dict

class ScannerFinding(BaseModel):
    tool: str
    target: str
    vulnerability: str
    severity: str
    description: str
    evidence: Optional[str] = None
    reference: Optional[str] = None

class TriageResult(BaseModel):
    target: str
    vulnerability: str
    validated_severity: str
    confidence_score: int
    threat_explanation: str
    remediation_guidance: str
    retrieved_references: List[str]
    status: str

class HistoricalScanRequest(BaseModel):
    scan_id: str
    previous_scan_id: Optional[str] = None
    target: str
    findings: List[ScannerFinding]

class ScanRunRecord(BaseModel):
    scan_id: str
    target: str
    scanner_tools_used: str
    findings: List[ScannerFinding]

class FindingSummary(BaseModel):
    vulnerability_title: str
    severity: str
    status: str

class ScanSummary(BaseModel):
    scan_id: str
    timestamp: str
    scanner_tools_used: str
    total_findings: int
    findings_summary: List[FindingSummary]

class DeltaReport(BaseModel):
    target: str
    previous_scan_id: str
    current_scan_id: str
    new_findings: List[ScannerFinding]
    persistent_findings: List[ScannerFinding]
    resolved_findings: List[ScannerFinding]
    summary: Dict[str, int]
