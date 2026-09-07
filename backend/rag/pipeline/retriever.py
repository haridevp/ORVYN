"""
Retrieves relevant knowledge chunks from ChromaDB for a set of queries,
then dedupes/trims into a single context block.
"""

import sys
import os

os.environ["ANONYMIZED_TELEMETRY"] = "False"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loaders.load_to_chroma import get_collection, get_embedder
from pipeline.config import TOP_K, MAX_CONTEXT_CHARS, MAX_CHUNKS, DISTANCE_THRESHOLD


def retrieve(queries: list[str], top_k: int = TOP_K, filters: dict = None) -> list[tuple]:
    """Returns list of (document, metadata, distance) across all queries."""
    collection = get_collection()
    embedder = get_embedder()

    all_hits = []
    for q in queries:
        q_emb = embedder.encode(q).tolist()
        results = collection.query(
            query_embeddings=[q_emb],
            n_results=top_k,
            where=filters
        )
        docs = results["documents"][0]
        metas = results["metadatas"][0]
        dists = results["distances"][0]
        all_hits.extend(zip(docs, metas, dists))

    return all_hits


def build_context(hits: list[tuple], max_chunks: int = MAX_CHUNKS,
                   max_chars: int = MAX_CONTEXT_CHARS,
                   distance_threshold: float = DISTANCE_THRESHOLD) -> tuple[str, list[dict]]:
    """
    Dedupes by title, drops weak matches above distance_threshold,
    sorts by relevance, and trims to a character budget.
    Returns (context_string, list_of_source_metadata).
    """
    # filter weak matches
    filtered = [h for h in hits if h[2] <= distance_threshold]
    if not filtered:
        # fall back to best available even if above threshold, rather than empty context
        filtered = sorted(hits, key=lambda x: x[2])[:max_chunks]

    # sort by distance (best first)
    filtered.sort(key=lambda x: x[2])

    # dedupe by title
    seen = set()
    deduped = []
    for doc, meta, dist in filtered:
        key = meta.get("title", doc[:50])
        if key not in seen:
            seen.add(key)
            deduped.append((doc, meta, dist))

    selected = deduped[:max_chunks]

    context_blocks = []
    total_len = 0
    used_sources = []
    for doc, meta, dist in selected:
        block = f"[Source: {meta.get('source')} - {meta.get('title')}]\n{doc}"
        if total_len + len(block) > max_chars:
            break
        context_blocks.append(block)
        used_sources.append(meta)
        total_len += len(block)

    return "\n\n".join(context_blocks), used_sources


if __name__ == "__main__":
    from pipeline.query_gen import generate_queries

    sample = {"vulnerability": "SQL Injection", "reference": "CWE-89"}
    queries = generate_queries(sample)
    hits = retrieve(queries)
    context, sources = build_context(hits)

    print(f"Retrieved {len(hits)} raw hits -> {len(sources)} used after dedup/trim\n")
    print(context[:1000])