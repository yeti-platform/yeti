from typing import cast

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict

from core.database_arango import ArangoYetiConnector

# API endpoints
router = APIRouter()


class SearchRequest(BaseModel):
    """Search request message."""

    model_config = ConfigDict(extra="forbid")

    query: dict[str, str | int | list] = {}
    sorting: list[tuple[str, bool]] = []
    filter_aliases: list[tuple[str, str]] = []
    count: int = 50
    page: int = 0


class SearchResponse(BaseModel):
    """Search response message."""

    results: list[dict]
    total: int = 0


class SemanticSearchRequest(BaseModel):
    """Semantic Search Request."""

    model_config = ConfigDict(extra="forbid")

    query: str
    count: int = 10


@router.post("/")
def search(httpreq: Request, request: SearchRequest) -> SearchResponse:
    """Gets the system config."""
    results, total = ArangoYetiConnector.filter(
        request.query,
        sorting=request.sorting,
        aliases=request.filter_aliases,
        count=request.count,
        offset=request.page * request.count,
        links_count=True,
        user=httpreq.state.user,
    )
    return SearchResponse(results=cast("list[dict]", results), total=total)


@router.post("/semantic")
def semantic_search(request: SemanticSearchRequest) -> SearchResponse:
    """Performs a semantic search on Yeti objects."""
    from core.chromadb_client import get_semantic_collection

    collection = get_semantic_collection()

    results = collection.query(query_texts=[request.query], n_results=request.count)

    object_metadatas = results.get("metadatas", [[{}]])[0]

    from core.schemas.dfiq import DFIQBase
    from core.schemas.entity import Entity
    from core.schemas.indicator import Indicator

    id_to_class = {"entities": Entity, "indicators": Indicator, "dfiq": DFIQBase}

    # Fetch real yeti objects from Arango
    yeti_objects = []
    for meta in object_metadatas:
        if "id" in meta and "collection" in meta:
            col = meta["collection"]
            cls = id_to_class.get(col)
            if cls:
                obj = cls.get(meta["id"])
                if obj:
                    yeti_objects.append(obj.model_dump())

    return SearchResponse(results=yeti_objects, total=len(yeti_objects))
