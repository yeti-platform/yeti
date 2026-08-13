import os

import chromadb
from chromadb.api.shared_system_client import SharedSystemClient

from core.config.config import yeti_config


def get_client() -> chromadb.ClientAPI:
    """Returns a configurable ChromaDB client.

    PersistentClient caches its underlying connection per Python process
    (SharedSystemClient._identifier_to_system, a process-wide dict): once a
    process has constructed one, later PersistentClient(...) calls in that
    *same* process reuse it rather than re-reading disk. That's fine for a
    single writer, but the indexer (celery worker) and this endpoint's
    caller (the API server) are separate long-running processes -- without
    clearing the cache first, the API process would keep serving whatever
    snapshot it had cached at its own startup, oblivious to anything the
    indexer wrote afterwards, until the API process itself restarts.
    Measured cost of clearing on every call: no observable difference.
    """
    SharedSystemClient.clear_system_cache()

    path = yeti_config.get("chromadb", "path", "/data/chromadb")

    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

    client = chromadb.PersistentClient(path=path)
    return client


def get_semantic_collection():
    client = get_client()
    return client.get_or_create_collection(name="yeti_semantic_search")
