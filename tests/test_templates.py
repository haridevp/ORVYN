from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "backend"))

for _name in ("schemas", "references", "correlation", "job_manager", "scanners", "templates", "environment", "mcp"):
    sys.modules.pop(_name, None)

from fastapi.testclient import TestClient
from src.backend.main import app
from src.backend.templates import template_registry, BUILTIN_TEMPLATES

client = TestClient(app)


def test_builtin_templates_exist():
    templates = template_registry.list_templates()
    assert len(templates) >= 6
    ids = [t.id for t in templates]
    assert "web_owasp_deep_audit" in ids
    assert "full_infrastructure_audit" in ids
    assert "api_microservice_audit" in ids
    assert "cms_wordpress_deep_audit" in ids
    assert "cloud_secrets_exposure_audit" in ids
    assert "quick_recon_triage" in ids


def test_template_details_and_toolchains():
    owasp_tmpl = template_registry.get_template("web_owasp_deep_audit")
    assert owasp_tmpl is not None
    assert owasp_tmpl.name == "OWASP Top 10 Exhaustive Web Audit"
    assert len(owasp_tmpl.tool_chain) >= 5
    assert owasp_tmpl.is_default is True
    assert "owasp" in owasp_tmpl.nuclei_tags


def test_recommend_template_heuristic():
    # WordPress detection
    tmpl = template_registry.recommend_template_for_tech(["WordPress 6.4", "PHP 8.2"])
    assert tmpl.id == "cms_wordpress_deep_audit"

    # API detection
    tmpl_api = template_registry.recommend_template_for_tech(["FastAPI", "Swagger UI"])
    assert tmpl_api.id == "api_microservice_audit"

    # Network / Infrastructure detection
    tmpl_infra = template_registry.recommend_template_for_tech(["Linux"], open_ports=[22, 3306, 5432])
    assert tmpl_infra.id == "full_infrastructure_audit"


def test_templates_api_endpoints():
    response = client.get("/templates")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 6

    # Test single template endpoint
    single_res = client.get("/templates/web_owasp_deep_audit")
    assert single_res.status_code == 200
    assert single_res.json()["id"] == "web_owasp_deep_audit"

    # Test 404 for unknown template
    missing_res = client.get("/templates/unknown-template-id")
    assert missing_res.status_code == 404


def test_scan_start_with_template():
    response = client.post(
        "/scan/start",
        json={
            "target": "template-demo.local",
            "scanners": ["nuclei", "whatweb"],
            "template": "full_infrastructure_audit",
        },
    )
    assert response.status_code == 202
    data = response.json()
    assert data["template_id"] == "full_infrastructure_audit"
    assert data["template_name"] == "Full Infrastructure & Network Audit"
