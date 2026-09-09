import asyncio
import logging
import sys
from pathlib import Path
from typing import Callable, Optional

# Ensure security_rag_engine is accessible on sys.path
_rag_engine_path = str(Path(__file__).resolve().parents[1] / "security_rag_engine")
if _rag_engine_path not in sys.path:
    sys.path.insert(0, _rag_engine_path)

logger = logging.getLogger("rag_triage")

_pipeline_instance = None


def get_pipeline():
    global _pipeline_instance
    if _pipeline_instance is None:
        try:
            from rag_pipeline import SecurityRAGPipeline
            _pipeline_instance = SecurityRAGPipeline()
            logger.info("SecurityRAGPipeline loaded successfully.")
        except Exception as e:
            logger.warning(f"Failed to initialize SecurityRAGPipeline: {e}")
            _pipeline_instance = False
    return _pipeline_instance if _pipeline_instance is not False else None


def triage_correlated_finding_sync(finding):
    """Enriches a single CorrelatedFinding with RAG context and LLM analysis."""
    pipeline = get_pipeline()
    if not pipeline:
        finding.ai_status = "unavailable"
        return finding

    try:
        from schemas import ScannerFinding as RAGScannerFinding

        tool_str = ", ".join([t.value if hasattr(t, "value") else str(t) for t in finding.contributing_tools])
        severity_val = finding.severity.value.lower() if hasattr(finding.severity, "value") else str(finding.severity).lower()

        rag_finding = RAGScannerFinding(
            tool=tool_str or "Multi-Scanner",
            target=finding.target,
            vulnerability=finding.vulnerability,
            severity=severity_val,
            description=finding.description,
            evidence="\n".join(finding.evidence) if finding.evidence else None,
        )

        result = pipeline.triage_finding(rag_finding)

        if result.status == "Error":
            finding.ai_status = "error"
            finding.ai_threat_explanation = result.threat_explanation
            finding.ai_remediation = result.remediation_guidance
            finding.ai_validated_severity = severity_val.capitalize()
            finding.ai_confidence = finding.confidence
        else:
            finding.ai_status = "completed"
            finding.ai_threat_explanation = result.threat_explanation
            finding.ai_remediation = result.remediation_guidance
            finding.ai_validated_severity = result.validated_severity
            finding.ai_confidence = result.confidence_score
            finding.ai_references = result.retrieved_references or []

    except Exception as e:
        logger.error(f"Error during RAG triage for {finding.vulnerability}: {e}")
        finding.ai_status = "unavailable"
        finding.ai_threat_explanation = f"AI analysis error: {e}"

    return finding


async def triage_all_correlated(
    findings: list,
    log_cb: Optional[Callable[[str], None]] = None
) -> list:
    """Asynchronously triages a list of CorrelatedFinding objects."""
    if not findings:
        return findings

    pipeline = get_pipeline()
    if not pipeline:
        if log_cb:
            log_cb("AI RAG Engine unavailable or not initialized. Skipping LLM triage.")
        for f in findings:
            f.ai_status = "unavailable"
        return findings

    if log_cb:
        log_cb(f"🤖 Starting AI RAG Triage on {len(findings)} correlated finding(s) with Qwen 2.5 (Ollama)...")

    for i, finding in enumerate(findings):
        if log_cb:
            log_cb(f"Analyzing [{i+1}/{len(findings)}]: {finding.vulnerability} on {finding.target}...")

        # Run in thread pool to avoid blocking async event loop
        enriched = await asyncio.to_thread(triage_correlated_finding_sync, finding)

        if log_cb and enriched.ai_status == "completed":
            log_cb(
                f"🎯 AI Triage completed for {finding.vulnerability}: "
                f"Validated Severity: {enriched.ai_validated_severity} (Confidence: {enriched.ai_confidence}%)"
            )

    if log_cb:
        log_cb("✨ AI RAG Triage complete. Knowledge citations and tailored remediations attached.")

    return findings
