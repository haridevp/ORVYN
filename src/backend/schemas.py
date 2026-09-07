from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


SEVERITY_ORDER = {
    Severity.critical: 4,
    Severity.high: 3,
    Severity.medium: 2,
    Severity.low: 1,
    Severity.info: 0,
}


class ScannerName(str, Enum):
    nuclei = "nuclei"
    zap = "zap"
    nikto = "nikto"


class ScannerRunState(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    error = "error"


class ScannerFinding(BaseModel):
    """Unified finding shape every scanner wrapper must normalize into."""

    id: str = Field(default_factory=lambda: f"finding-{uuid4().hex[:10]}")
    tool: ScannerName
    target: str
    vulnerability: str
    severity: Severity
    description: str
    evidence: Optional[str] = None
    reference: Optional[str] = None


class ScanStartRequest(BaseModel):
    target: str = Field(..., min_length=3, description="Hostname, IP, or URL to assess")
    scanners: list[ScannerName] = Field(
        default_factory=lambda: [ScannerName.nuclei, ScannerName.zap, ScannerName.nikto],
        description="Which scanners to run for this job",
    )
    profile: Literal["recon", "web", "full", "unlimited"] = "web"
    in_scope: list[str] = Field(
        default_factory=list,
        description="Domains, subdomains, or wildcard patterns in scope (e.g. *.target.com)",
    )
    out_of_scope: list[str] = Field(
        default_factory=list,
        description="Excluded domains, endpoints, or keywords (e.g. logout, auth.*)",
    )
    requested_by: str = Field(default="panel-review-demo")


class ScannerProgress(BaseModel):
    tool: ScannerName
    status: ScannerRunState
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    findings_count: int = 0
    error: Optional[str] = None
    simulated: bool = False


class SeverityDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanStatusResponse(BaseModel):
    scan_id: str
    target: str
    profile: str
    overall_status: Literal["queued", "running", "completed", "error"]
    progress_pct: int = 0
    eta_seconds: Optional[int] = None
    elapsed_seconds: int = 0
    scanners: list[ScannerProgress]
    live_findings: list[ScannerFinding] = Field(default_factory=list)
    findings_count: int = 0
    severity_distribution: SeverityDistribution = Field(default_factory=SeverityDistribution)
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    logs: list[str] = Field(default_factory=list)
    created_at: str
    updated_at: str


class CorrelatedFinding(BaseModel):
    """A consolidated finding after de-duplication/correlation across tools."""

    correlation_id: str
    target: str
    vulnerability: str
    severity: Severity
    confidence: int = Field(..., ge=0, le=100)
    contributing_tools: list[ScannerName]
    conflicting_severity: bool
    description: str
    evidence: list[str]
    reference: Optional[str] = None
    source_finding_ids: list[str]


class ScanResultsResponse(BaseModel):
    scan_id: str
    target: str
    overall_status: str
    raw_findings: list[ScannerFinding]
    correlated_findings: list[CorrelatedFinding]
    severity_distribution: SeverityDistribution
    duplicate_groups: int
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    logs: list[str] = Field(default_factory=list)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
