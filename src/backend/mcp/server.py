"""HexStrike Model Context Protocol (MCP) Server Interface.

Exposes security toolchains and templates via standard MCP-compliant tool schemas
and JSON-RPC/REST endpoints for AI agents and LLM orchestrators.
"""

from typing import Any, Optional
from fastapi import APIRouter, HTTPException
import httpx
from pydantic import BaseModel, Field

from environment import detect_environment, EnvironmentInfo
from mcp.runner import hexstrike_runner
from templates.definitions import ScanTemplate
from templates.registry import template_registry

mcp_router = APIRouter(prefix="/mcp", tags=["HexStrike MCP Engine"])


# MCP Schema Specifications
class MCPToolDefinition(BaseModel):
    name: str
    description: str
    parameters: dict[str, Any]


class VulnerabilityVerificationRequest(BaseModel):
    target: str = Field(..., description="Target host or base URL")
    endpoint: Optional[str] = Field(default=None, description="Path to verify, e.g. /.git/HEAD")
    finding_title: str = Field(..., description="Vulnerability title to verify")
    expected_evidence_pattern: Optional[str] = Field(default=None, description="Regex or string pattern in response")


class VulnerabilityVerificationResult(BaseModel):
    target: str
    finding_title: str
    verified: bool
    status_code: Optional[int] = None
    evidence_found: Optional[str] = None
    notes: str


CURATED_MCP_TOOLS: list[MCPToolDefinition] = [
    MCPToolDefinition(
        name="hexstrike_list_templates",
        description="Returns all curated multi-tool vulnerability assessment templates, their chained tools, and targeted vulnerability classes.",
        parameters={"type": "object", "properties": {}},
    ),
    MCPToolDefinition(
        name="hexstrike_detect_environment",
        description="Detects whether the platform is running on Kali Linux, Parrot OS, Docker container, or fallback mode, and lists available tools.",
        parameters={"type": "object", "properties": {}},
    ),
    MCPToolDefinition(
        name="hexstrike_recommend_template",
        description="Analyzes discovered technology stack and recommends the optimal multi-tool audit template for maximum vulnerability discovery.",
        parameters={
            "type": "object",
            "properties": {
                "technologies": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of detected technologies (e.g. ['WordPress 6.4', 'PHP 8.2', 'Nginx'])",
                },
                "open_ports": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "List of discovered open TCP ports (e.g. [80, 443, 22, 3306])",
                },
            },
            "required": ["technologies"],
        },
    ),
    MCPToolDefinition(
        name="hexstrike_verify_vulnerability",
        description="Executes a safe, targeted verification check on an endpoint to confirm a suspected vulnerability and eliminate false positives.",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target hostname or base URL"},
                "endpoint": {"type": "string", "description": "Target path, e.g. '/.env' or '/wp-json/wp/v2/users'"},
                "finding_title": {"type": "string", "description": "Name of the finding"},
                "expected_evidence_pattern": {"type": "string", "description": "Expected string in body or headers"},
            },
            "required": ["target", "finding_title"],
        },
    ),
]


@mcp_router.get("/tools", response_model=list[MCPToolDefinition])
def list_mcp_tools() -> list[MCPToolDefinition]:
    """List all available curated tools exposed by the HexStrike MCP server."""
    return CURATED_MCP_TOOLS


@mcp_router.get("/environment", response_model=EnvironmentInfo)
def get_mcp_environment() -> EnvironmentInfo:
    """Return OS detection, Kali/Parrot native status, and available tool binaries."""
    return detect_environment()


@mcp_router.get("/templates", response_model=list[ScanTemplate])
def list_mcp_templates() -> list[ScanTemplate]:
    """Return all registered multi-tool assessment templates."""
    return template_registry.list_templates()


class RecommendRequest(BaseModel):
    technologies: list[str]
    open_ports: Optional[list[int]] = None


@mcp_router.post("/templates/recommend", response_model=ScanTemplate)
def recommend_template(req: RecommendRequest) -> ScanTemplate:
    """Recommend an audit template based on target tech stack or open ports."""
    return template_registry.recommend_template_for_tech(req.technologies, req.open_ports)


@mcp_router.post("/verify", response_model=VulnerabilityVerificationResult)
async def verify_vulnerability_endpoint(req: VulnerabilityVerificationRequest) -> VulnerabilityVerificationResult:
    """Verify a finding one-by-one by probing the target endpoint directly."""
    base = req.target.strip()
    if not base.startswith(("http://", "https://")):
        base = f"http://{base}"

    url = f"{base.rstrip('/')}/{req.endpoint.lstrip('/')}" if req.endpoint else base

    try:
        async with httpx.AsyncClient(timeout=4.0, verify=False) as client:
            resp = await client.get(url, follow_redirects=True)
            text = resp.text[:4000]

            # Common pattern checks
            is_verified = False
            evidence = None

            if req.expected_evidence_pattern:
                if req.expected_evidence_pattern.lower() in text.lower():
                    is_verified = True
                    evidence = f"Matched pattern '{req.expected_evidence_pattern}' in response"
            elif resp.status_code == 200:
                # Basic sanity heuristic
                if req.endpoint and req.endpoint.lower() in [".env", ".git/head", "wp-config.php"]:
                    if any(kw in text.lower() for kw in ["db_password", "ref: refs/heads", "mysql_connect"]):
                        is_verified = True
                        evidence = f"Sensitive content exposed at {req.endpoint} (HTTP 200)"
                elif "header" in req.finding_title.lower():
                    # Check if security header is missing
                    missing_h = [h for h in ["content-security-policy", "x-frame-options"] if h not in resp.headers]
                    if missing_h:
                        is_verified = True
                        evidence = f"Missing security headers: {', '.join(missing_h)}"

            return VulnerabilityVerificationResult(
                target=req.target,
                finding_title=req.finding_title,
                verified=is_verified,
                status_code=resp.status_code,
                evidence_found=evidence,
                notes=f"Probed {url} -> HTTP {resp.status_code}. Verified: {is_verified}",
            )
    except Exception as exc:
        return VulnerabilityVerificationResult(
            target=req.target,
            finding_title=req.finding_title,
            verified=False,
            status_code=None,
            evidence_found=None,
            notes=f"Verification probe failed: {exc}",
        )
