"""
End-to-end RAG pipeline: consolidated finding -> queries -> retrieval ->
context -> prompt -> LLM -> structured AI analysis.

This is the single function Member 1 (dashboard) and Member 4 (triage)
should call/import.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.query_gen import generate_queries
from pipeline.retriever import retrieve, build_context
from pipeline.prompt_builder import build_prompt
from pipeline.llm_client import run_ai_analysis
from pipeline.config import LLM_MODEL, TOP_K


def rag_pipeline(finding: dict, use_rag: bool = True, model: str = None) -> dict:
    """
    Runs the full RAG pipeline on a single consolidated finding.
    Set use_rag=False to run scanner-only (no retrieval) — useful for
    the ablation study comparing with/without RAG.
    """
    if use_rag:
        queries = generate_queries(finding)
        hits = retrieve(queries, top_k=TOP_K)
        context, sources = build_context(hits)
    else:
        context, sources = "", []

    prompt = build_prompt(finding, context)
    analysis = run_ai_analysis(prompt, model=model)

    analysis["retrieved_sources"] = sources
    analysis["used_rag"] = use_rag
    analysis["model"] = model or LLM_MODEL
    analysis["finding_id"] = finding.get("id")

    return analysis


if __name__ == "__main__":
    import json

    with open(os.path.join(os.path.dirname(__file__), "..", "eval", "test_findings.json")) as f:
        findings = json.load(f)

    result = rag_pipeline(findings[0])
    print(json.dumps(result, indent=2))