"""
Sanity check script: queries the populated ChromaDB collection with a
handful of known security terms and prints back what's retrieved, to
confirm the KB was built correctly before the pipeline branch depends on it.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from loaders.load_to_chroma import get_collection, get_embedder

TEST_QUERIES = [
    "SQL injection in login form",
    "cross-site scripting vulnerability",
    "server-side request forgery",
    "broken authentication and session management",
    "insecure deserialization remote code execution",
    "MITRE ATT&CK technique for privilege escalation",
]


def run_test_queries(top_k=5):
    collection = get_collection()
    embedder = get_embedder()

    print(f"Collection has {collection.count()} total chunks.\n")

    for query in TEST_QUERIES:
        print(f"{'='*70}")
        print(f"QUERY: {query}")
        print('='*70)

        q_embedding = embedder.encode(query).tolist()
        results = collection.query(
            query_embeddings=[q_embedding],
            n_results=top_k
        )

        docs = results["documents"][0]
        metas = results["metadatas"][0]
        distances = results["distances"][0]

        for doc, meta, dist in zip(docs, metas, distances):
            print(f"\n  [{meta['source']}] {meta['title']}  (distance: {dist:.4f})")
            print(f"  {doc[:150]}...")

        print()


if __name__ == "__main__":
    run_test_queries()