"""
Central config for the RAG pipeline. Change LLM_MODEL here (or override
via environment variable) — nothing else in the pipeline should hardcode
a model name.
"""

import os

# Default model used for local dev/testing — override via env var when
# integrating with a different model (e.g. mistral).
LLM_MODEL = os.environ.get("RAG_LLM_MODEL", "qwen2.5:7b")

# Retrieval defaults
TOP_K = int(os.environ.get("RAG_TOP_K", 3))
MAX_CONTEXT_CHARS = int(os.environ.get("RAG_MAX_CONTEXT_CHARS", 2500))
MAX_CHUNKS = int(os.environ.get("RAG_MAX_CHUNKS", 5))
DISTANCE_THRESHOLD = float(os.environ.get("RAG_DISTANCE_THRESHOLD", 0.45))  # discard weak matches