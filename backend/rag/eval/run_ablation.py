"""
Runs the pipeline on all test findings, with and without RAG, and saves
results for manual comparison/scoring.
"""

import sys
import os
import json
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from pipeline.pipeline import rag_pipeline

FINDINGS_PATH = os.path.join(os.path.dirname(__file__), "test_findings.json")
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "ablation_results.json")


def run_ablation():
    with open(FINDINGS_PATH) as f:
        findings = json.load(f)

    results = []
    for i, finding in enumerate(findings):
        print(f"[{i+1}/{len(findings)}] Processing {finding['id']} ({finding['vulnerability']})...")

        start = time.time()
        no_rag = rag_pipeline(finding, use_rag=False)
        no_rag_time = time.time() - start

        start = time.time()
        with_rag = rag_pipeline(finding, use_rag=True)
        with_rag_time = time.time() - start

        results.append({
            "finding_id": finding["id"],
            "vulnerability": finding["vulnerability"],
            "scanner_reported_severity": finding["severity"],
            "no_rag_result": no_rag,
            "no_rag_time_sec": round(no_rag_time, 2),
            "with_rag_result": with_rag,
            "with_rag_time_sec": round(with_rag_time, 2),
        })

    with open(OUTPUT_PATH, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[✓] Saved {len(results)} comparisons to {OUTPUT_PATH}")


if __name__ == "__main__":
    run_ablation()  