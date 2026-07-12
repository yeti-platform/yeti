import os

import chromadb

from core.config.config import yeti_config


def get_client() -> chromadb.ClientAPI:
    """Returns a configurable ChromaDB client."""
    path = yeti_config.get("chromadb", "path", "/data/chromadb")

    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

    client = chromadb.PersistentClient(path=path)
    return client


def get_semantic_collection():
    client = get_client()
    return client.get_or_create_collection(name="yeti_semantic_search")
