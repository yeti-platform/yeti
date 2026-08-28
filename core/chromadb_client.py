import os
import urllib.parse

import chromadb
from chromadb.api.shared_system_client import SharedSystemClient
from chromadb.config import Settings

from core.config.config import yeti_config

SEMANTIC_COLLECTION_NAME = "yeti_semantic_search"

# ChromaDB's own default when a URL carries no port.
DEFAULT_SERVER_PORT = 8000


def _settings() -> Settings:
    """Builds the Settings a Yeti-owned client is constructed with.

    Returned fresh each time rather than shared: HttpClient *writes* the host,
    port and api_impl it was given into the Settings object it is handed, and
    refuses a second connection whose host disagrees with what it finds there.

    chromadb posts anonymized usage events to PostHog by default. Yeti is
    deployed on networks with no outbound internet access, where those calls
    only cost latency and log noise.
    """
    return Settings(anonymized_telemetry=False)


def _server_client(http_root: str) -> chromadb.ClientAPI:
    """Connects to a ChromaDB server that owns the index.

    The server is the single source of truth, so the per-process snapshot the
    embedded client keeps -- and has to be told to drop -- cannot form here.

    HttpClient wants a host and a port and uses whatever string it is handed
    verbatim, so the URL is split up here instead: that lets this setting be
    written like every other service Yeti points at (see the `agents` section)
    rather than being the one that silently misbehaves if given a scheme.
    """
    parsed = urllib.parse.urlparse(http_root)
    if not parsed.hostname:
        raise ValueError(
            f"chromadb.http_root is not a URL Yeti can connect to: {http_root!r}. "
            "Expected something like http://chromadb:8000"
        )

    ssl = parsed.scheme == "https"
    return chromadb.HttpClient(
        host=parsed.hostname,
        port=parsed.port or (443 if ssl else DEFAULT_SERVER_PORT),
        ssl=ssl,
        settings=_settings(),
    )


def _embedded_client() -> chromadb.ClientAPI:
    """Opens the on-disk index directly, in this process.

    PersistentClient caches its underlying connection per Python process
    (SharedSystemClient._identifier_to_system, a process-wide dict): once a
    process has constructed one, later PersistentClient(...) calls in that
    *same* process reuse it rather than re-reading disk. That's fine for a
    single writer, but the indexer (celery worker) and the search endpoint's
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

    return chromadb.PersistentClient(path=path, settings=_settings())


def get_client() -> chromadb.ClientAPI:
    """Returns a client for whichever ChromaDB backend is configured.

    Embedded by default, which requires every process touching the index to
    see the same filesystem. That holds on a single host and stops holding the
    moment the API and the indexer are scheduled apart: each opens its own copy,
    so writes land in one and reads come back empty from the other with no error
    raised on either side. It is also SQLite, whose locking is unreliable on
    shared network filesystems, so a common volume is not a fix.

    Setting `chromadb.http_root` points every process at one server instead.
    Embeddings are still computed in this process either way -- the server
    stores and searches vectors, it is never handed text -- so a deployment
    without internet access needs the model available here, not there.
    """
    http_root = yeti_config.get("chromadb", "http_root")
    if http_root:
        return _server_client(http_root)
    return _embedded_client()


def get_semantic_collection(client: chromadb.ClientAPI | None = None):
    """Returns the collection every semantically-indexed object lives in.

    Callers that also need client-level information -- the write batch limit,
    say -- should build the client once and pass it in rather than calling
    get_client() a second time, since each call clears the process-wide system
    cache that an already-returned embedded collection resolves through.
    """
    client = client or get_client()
    return client.get_or_create_collection(name=SEMANTIC_COLLECTION_NAME)
