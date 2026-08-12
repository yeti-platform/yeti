from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict

from core.database_arango import ArangoYetiConnector

# API endpoints
router = APIRouter()


class SearchRequest(BaseModel):
    """Global search request message."""

    model_config = ConfigDict(extra="forbid")

    query: str
    count_per_type: int = 5


class SearchResultSection(BaseModel):
    """One type's bucket of results in a grouped search response."""

    type: str
    results: list[dict]
    total: int = 0


class SearchResponse(BaseModel):
    """Global search response message."""

    sections: list[SearchResultSection]


class SemanticSearchRequest(BaseModel):
    """Semantic Search Request."""

    model_config = ConfigDict(extra="forbid")

    query: str
    count: int = 10


class SemanticSearchResponse(BaseModel):
    """Semantic Search Response."""

    results: list[dict]
    total: int = 0


@router.post("/")
def search(httpreq: Request, request: SearchRequest) -> SearchResponse:
    """Searches across all object types, bucketed by type.

    Each type gets its own bounded slice of results, so a substring match
    in one type's field (e.g. an observable hash) can't drown out matches
    from another type (e.g. an entity name).
    """
    sections = ArangoYetiConnector.grouped_search(
        request.query,
        count_per_type=request.count_per_type,
        user=httpreq.state.user,
    )
    return SearchResponse(sections=[SearchResultSection(**s) for s in sections])


@router.post("/semantic")
def semantic_search(request: SemanticSearchRequest) -> SemanticSearchResponse:
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

    return SemanticSearchResponse(results=yeti_objects, total=len(yeti_objects))
