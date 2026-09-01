import chromadb
from chromadb.utils import embedding_functions
from config import CHROMA_PERSIST_DIR, EMBEDDING_MODEL

def get_chroma_client():
    return chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)

def get_embedding_function():
    return embedding_functions.SentenceTransformerEmbeddingFunction(model_name=EMBEDDING_MODEL)

def get_collection(name: str = "security_knowledge"):
    client = get_chroma_client()
    ef = get_embedding_function()
    collection = client.get_or_create_collection(
        name=name,
        embedding_function=ef
    )
    return collection
