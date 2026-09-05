"""
Embeds and loads chunked documents into a persistent ChromaDB collection
named 'security_knowledge'.

Uses upsert (not add) so re-running the pipeline is idempotent — safe to
refresh sources later without duplicate errors.
"""

import os
import chromadb
from sentence_transformers import SentenceTransformer

CHROMA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "chroma_db")
COLLECTION_NAME = "security_knowledge"
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"

_client = None
_embedder = None
_collection = None


def get_client():
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(path=CHROMA_PATH)
    return _client


def get_embedder():
    global _embedder
    if _embedder is None:
        print(f"[*] Loading embedding model: {EMBEDDING_MODEL}")
        _embedder = SentenceTransformer(EMBEDDING_MODEL)
    return _embedder


def get_collection():
    global _collection
    if _collection is None:
        client = get_client()
        _collection = client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"}
        )
    return _collection


def load_chunks(chunks, batch_size=64):
    """
    chunks: list of {id, document, metadata} dicts.
    Embeds in batches and upserts into the ChromaDB collection.
    """
    collection = get_collection()
    embedder = get_embedder()

    total = len(chunks)
    for i in range(0, total, batch_size):
        batch = chunks[i:i + batch_size]
        ids = [c["id"] for c in batch]
        docs = [c["document"] for c in batch]
        metas = [c["metadata"] for c in batch]

        embeddings = embedder.encode(docs, show_progress_bar=False).tolist()

        collection.upsert(
            ids=ids,
            documents=docs,
            metadatas=metas,
            embeddings=embeddings
        )

        done = min(i + batch_size, total)
        print(f"    -> loaded {done}/{total} chunks")

    print(f"[✓] Collection '{COLLECTION_NAME}' now has {collection.count()} total chunks")


if __name__ == "__main__":
    # quick standalone smoke test with fake data
    test_chunks = [
        {
            "id": "test-chunk-0",
            "document": "SQL injection allows attackers to execute arbitrary SQL via unsanitized input.",
            "metadata": {"source": "TEST", "source_id": "TEST-1", "title": "SQL Injection Test", "url": "", "chunk_index": 0}
        }
    ]
    load_chunks(test_chunks)
    print("Smoke test passed.")