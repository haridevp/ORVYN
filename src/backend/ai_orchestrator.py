"""AI Autonomous Orchestrator (Module 4).

Autonomous LLM-driven decision engine using local Qwen 2.5 (Ollama) to:
1. Analyze initial reconnaissance findings (technologies, ports, banners).
2. Select the optimal multi-tool vulnerability assessment template from the 30 available templates.
3. Formulate targeted secondary attack chains and verify findings.
"""

import json
import logging
import os
import re
from typing import Any, Optional
import httpx
from pydantic import BaseModel, Field

try:
    from templates.definitions import ScanTemplate
    from templates.registry import template_registry
except Exception:
    import importlib
    _tmpl_defs = importlib.import_module("src.backend.templates.definitions")
    _tmpl_reg = importlib.import_module("src.backend.templates.registry")
    ScanTemplate = _tmpl_defs.ScanTemplate
    template_registry = _tmpl_reg.template_registry

logger = logging.getLogger("ai_orchestrator")

OLLAMA_API_BASE = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434/v1")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")


class TemplateSelectionResult(BaseModel):
    selected_template_id: str
    template_name: str
    confidence: int
    reasoning: str
    recommended_nuclei_tags: list[str] = Field(default_factory=list)
    is_llm_decided: bool = True


SYSTEM_PROMPT = """You are an elite Autonomous Penetration Testing Orchestrator.
Your job is to analyze initial reconnaissance data from a target perimeter and select the single BEST vulnerability assessment template to execute next for maximum vulnerability discovery.

Rules:
1. Return strictly a raw JSON object with NO markdown formatting, NO backticks, and NO conversational filler.
2. The JSON object must match this schema:
{
  "selected_template_id": "<must be an exact ID from the available templates list>",
  "confidence": <integer between 50 and 100>,
  "reasoning": "<concise 1-2 sentence technical justification for this choice>",
  "recommended_nuclei_tags": ["<tag1>", "<tag2>"]
}
"""


async def select_template_with_llm(
    target: str,
    technologies: list[str],
    open_ports: Optional[list[int]] = None,
    server_banner: Optional[str] = None,
    timeout_sec: float = 15.0,
) -> TemplateSelectionResult:
    """Ask local LLM (Qwen 2.5) or cloud LLM to select the optimal audit template based on recon findings."""
    all_templates = template_registry.list_templates()
    templates_catalog = "\n".join(
        [f"- ID: {t.id} | Name: {t.name} | Category: {t.category} | Focus: {', '.join(t.vulnerability_focus[:3])}" for t in all_templates]
    )

    ports_str = ", ".join(map(str, open_ports)) if open_ports else "80, 443 (default HTTP/HTTPS)"
    tech_str = ", ".join(technologies) if technologies else "Standard Web Server"
    banner_str = server_banner or "Not specifically identified"

    user_prompt = f"""Perimeter Reconnaissance Findings:
- Target Host: {target}
- Detected Technologies: {tech_str}
- Discovered Open Ports: {ports_str}
- Server Banner / Headers: {banner_str}

Available Assessment Templates (Select the most appropriate one):
{templates_catalog}

Select the optimal template to uncover maximum vulnerabilities on this target."""

    candidate_bases = []
    if "OLLAMA_API_BASE" in os.environ:
        candidate_bases.append(os.environ["OLLAMA_API_BASE"])
    candidate_bases.extend([
        "http://localhost:11434/v1",
        "http://127.0.0.1:11434/v1",
        "http://host.docker.internal:11434/v1",
        "http://172.17.0.1:11434/v1",
    ])

    for base_url in candidate_bases:
        try:
            async with httpx.AsyncClient(timeout=timeout_sec) as client:
                resp = await client.post(
                    f"{base_url}/chat/completions",
                    json={
                        "model": OLLAMA_MODEL,
                        "messages": [
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0.1,
                        "max_tokens": 250,
                    },
                )
                if resp.status_code == 200:
                    raw_content = resp.json()["choices"][0]["message"]["content"].strip()
                    cleaned = re.sub(r"^```json\s*", "", raw_content, flags=re.MULTILINE)
                    cleaned = re.sub(r"^```\s*", "", cleaned, flags=re.MULTILINE).strip()
                    parsed = json.loads(cleaned)

                    chosen_id = parsed.get("selected_template_id", "").strip()
                    matched_template = template_registry.get_template(chosen_id)
                    if matched_template:
                        return TemplateSelectionResult(
                            selected_template_id=matched_template.id,
                            template_name=matched_template.name,
                            confidence=int(parsed.get("confidence", 85)),
                            reasoning=str(parsed.get("reasoning", f"Selected by Qwen 2.5 for {tech_str}")),
                            recommended_nuclei_tags=parsed.get("recommended_nuclei_tags", matched_template.nuclei_tags),
                            is_llm_decided=True,
                        )
        except Exception:
            continue

    # Fallback to rule-based heuristic recommendation if LLM is offline or unparseable
    fallback_template = template_registry.recommend_template_for_tech(technologies, open_ports)
    return TemplateSelectionResult(
        selected_template_id=fallback_template.id,
        template_name=fallback_template.name,
        confidence=80,
        reasoning=f"Automated heuristic match based on detected components: {tech_str}",
        recommended_nuclei_tags=fallback_template.nuclei_tags,
        is_llm_decided=False,
    )
