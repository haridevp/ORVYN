
from fastapi.testclient import TestClient
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[2]))
sys.path.append(str(Path(__file__).resolve().parents[2] / "src" / "security_rag_engine"))

from src.security_rag_engine.main import app
from src.security_rag_engine.schemas import ScannerFinding
from src.security_rag_engine.rag_pipeline import SecurityRAGPipeline

client = TestClient(app)

def test_kb_seeding():
    response = client.post("/api/v1/kb/seed")
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["seeded_records"] > 0



def test_rag_pipeline_context_retrieval():
    # Make sure DB is seeded for this test
    client.post("/api/v1/kb/seed")
    
    pipeline = SecurityRAGPipeline()
    finding = ScannerFinding(
        tool="ZAP",
        target="http://example.com",
        vulnerability="SQL Injection",
        severity="Critical",
        description="SQL injection in login parameter"
    )
    
    contexts = pipeline.retrieve_context(finding, top_k=2)
    assert len(contexts) > 0
    # Ensure it's returning something related to SQL
    assert any("SQL" in ctx["content"] for ctx in contexts)

# We can mock the OpenAI call for testing prompt formation and JSON parsing
class MockChoice:
    class MockMessage:
        content = '{"target": "http://example.com", "vulnerability": "SQL Injection", "validated_severity": "Critical", "confidence_score": 95, "threat_explanation": "SQLi allows data exfiltration", "remediation_guidance": "Use prepared statements", "retrieved_references": ["https://cwe.mitre.org/data/definitions/89.html"], "status": "Triaged"}'
    message = MockMessage()

class MockResponse:
    choices = [MockChoice()]

def test_triage_finding_mock(monkeypatch):
    pipeline = SecurityRAGPipeline()
    finding = ScannerFinding(
        tool="ZAP",
        target="http://example.com",
        vulnerability="SQL Injection",
        severity="Critical",
        description="SQL injection in login parameter"
    )
    
    # Mock the LLM call
    def mock_create(*args, **kwargs):
        return MockResponse()
        
    monkeypatch.setattr(pipeline.client.chat.completions, "create", mock_create)
    
    result = pipeline.triage_finding(finding)
    assert result.validated_severity == "Critical"
    assert result.confidence_score == 95
    assert result.status == "Triaged"
    assert len(result.retrieved_references) > 0
