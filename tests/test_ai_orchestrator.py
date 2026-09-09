from pathlib import Path
import sys
import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "backend"))

for _name in ("schemas", "references", "correlation", "job_manager", "scanners", "templates", "environment", "mcp"):
    sys.modules.pop(_name, None)

from ai_orchestrator import select_template_with_llm
from templates.definitions import BUILTIN_TEMPLATES
from templates.registry import template_registry


def test_template_catalog_has_30_templates():
    templates = template_registry.list_templates()
    assert len(templates) == 30
    assert len(BUILTIN_TEMPLATES) == 30

    categories = template_registry.list_categories()
    assert len(categories) >= 5
    assert "CMS & Frameworks" in categories
    assert "API & Cloud" in categories
    assert "OWASP Injections" in categories
    assert "Infrastructure" in categories
    assert "Recon & Supply Chain" in categories


@pytest.mark.anyio
async def test_ai_orchestrator_selects_wordpress():
    decision = await select_template_with_llm("https://blog.example.com", ["WordPress 6.4", "PHP 8.2"])
    assert decision.selected_template_id == "cms_wordpress_deep_audit"
    assert "WordPress" in decision.reasoning or "heuristic" in decision.reasoning
    assert decision.confidence >= 50


@pytest.mark.anyio
async def test_ai_orchestrator_selects_kubernetes():
    decision = await select_template_with_llm("https://k8s.internal", ["Kubernetes", "etcd"])
    assert decision.selected_template_id == "cloud_kubernetes_metadata_audit"
    assert decision.confidence >= 50


@pytest.mark.anyio
async def test_ai_orchestrator_selects_api():
    decision = await select_template_with_llm("https://api.example.com/v1", ["FastAPI", "Swagger UI"])
    assert decision.selected_template_id == "api_microservice_audit"
    assert decision.confidence >= 50


@pytest.mark.anyio
async def test_ai_orchestrator_selects_database_exposure():
    decision = await select_template_with_llm("192.168.1.100", [], open_ports=[3306, 5432, 6379])
    assert decision.selected_template_id in ("full_infrastructure_audit", "database_exposure_audit")
