import os

import chromadb
from chromadb.api.shared_system_client import SharedSystemClient
from chromadb.config import Settings

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

    # chromadb posts anonymized usage events to PostHog by default. Yeti is
    # deployed on networks with no outbound internet access, where those calls
    # only cost latency and log noise.
    client = chromadb.PersistentClient(
        path=path, settings=Settings(anonymized_telemetry=False)
    )
    return client


SEMANTIC_COLLECTION_NAME = "yeti_semantic_search"


def get_semantic_collection(client: chromadb.ClientAPI | None = None):
    """Returns the collection every semantically-indexed object lives in.

    Callers that also need client-level information -- the write batch limit,
    say -- should build the client once and pass it in rather than calling
    get_client() a second time, since each call clears the process-wide system
    cache that an already-returned collection resolves through.
    """
    client = client or get_client()
    return client.get_or_create_collection(name=SEMANTIC_COLLECTION_NAME)
