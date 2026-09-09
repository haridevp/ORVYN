from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "backend"))

for _name in ("schemas", "references", "correlation", "job_manager", "scanners", "templates", "environment", "mcp"):
    sys.modules.pop(_name, None)

from fastapi.testclient import TestClient
from src.backend.main import app
from src.backend.environment import detect_environment, ExecutionMode

client = TestClient(app)


def test_detect_environment_structure():
    env = detect_environment()
    assert hasattr(env, "os_name")
    assert hasattr(env, "is_kali")
    assert hasattr(env, "is_parrot")
    assert hasattr(env, "docker_available")
    assert env.execution_mode in [
        ExecutionMode.NATIVE_KALI,
        ExecutionMode.NATIVE_PARROT,
        ExecutionMode.NATIVE_LINUX,
        ExecutionMode.DOCKERIZED_MCP,
        ExecutionMode.SIMULATED,
    ]


def test_environment_api_endpoint():
    response = client.get("/environment")
    assert response.status_code == 200
    data = response.json()
    assert "os_name" in data
    assert "execution_mode" in data
    assert "available_tools" in data


def test_mcp_tools_endpoint():
    response = client.get("/mcp/tools")
    assert response.status_code == 200
    tools = response.json()
    assert len(tools) >= 4
    tool_names = [t["name"] for t in tools]
    assert "hexstrike_list_templates" in tool_names
    assert "hexstrike_detect_environment" in tool_names
    assert "hexstrike_verify_vulnerability" in tool_names


def test_mcp_templates_and_recommendation():
    response = client.get("/mcp/templates")
    assert response.status_code == 200
    assert len(response.json()) >= 6

    # Test recommendation endpoint
    rec_res = client.post(
        "/mcp/templates/recommend",
        json={"technologies": ["WordPress 6.4", "WooCommerce"]},
    )
    assert rec_res.status_code == 200
    assert rec_res.json()["id"] == "cms_wordpress_deep_audit"
