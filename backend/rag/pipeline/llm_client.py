"""
Wraps Ollama chat calls. Model name comes from pipeline/config.py so it
can be swapped (qwen2.5:3b locally, mistral in integration) via env var
without touching this file.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import ollama
from pipeline.config import LLM_MODEL


def run_ai_analysis(prompt: str, model: str = None, retries: int = 2) -> dict:
    model = model or LLM_MODEL

    last_error = None
    raw = None
    for attempt in range(retries + 1):
        try:
            response = ollama.chat(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                format="json"
            )
            raw = response["message"]["content"]
            return json.loads(raw)
        except json.JSONDecodeError as e:
            last_error = e
            print(f"  [!] JSON parse failed (attempt {attempt+1}), raw output: {raw[:200] if raw else 'N/A'}")
        except Exception as e:
            last_error = e
            print(f"  [!] Ollama call failed (attempt {attempt+1}): {e}")

    return {
        "error": f"Failed after {retries+1} attempts: {last_error}",
        "explanation": None,
        "severity": None,
        "confidence": 0,
        "remediation": None
    }


if __name__ == "__main__":
    test_prompt = """Respond ONLY with JSON: {"status": "ok", "model_check": true}"""
    result = run_ai_analysis(test_prompt)
    print(result)