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
def semantic_search(
    httpreq: Request, request: SemanticSearchRequest
) -> SemanticSearchResponse:
    """Performs a semantic search on Yeti objects.

    Results come from a nearest-neighbor lookup in ChromaDB, which knows
    nothing about ACLs, so each candidate is checked individually against
    the calling user's permissions before being returned.
    """
    from core.chromadb_client import get_semantic_collection
    from core.schemas import rbac, roles

    collection = get_semantic_collection()

    user = httpreq.state.user
    enforce_acls = rbac.RBAC_ENABLED and not user.admin

    # ACL filtering happens after the nearest-neighbor search, so overfetch to
    # absorb candidates the user can't see and still have a shot at `count`
    # results -- not a guarantee: if visibility is narrow enough, fewer than
    # `count` results can still come back even after overfetching.
    fetch_count = request.count * 3 if enforce_acls else request.count
    results = collection.query(query_texts=[request.query], n_results=fetch_count)

    object_metadatas = results.get("metadatas", [[{}]])[0]
    # ChromaDB returns nearest (most similar) first; distance is a cosine
    # distance (0 = identical, larger = less similar). Surface it as a
    # bounded-ish "higher is better" score instead, so consumers don't have
    # to know chroma's convention or re-derive one themselves.
    distances = results.get("distances", [[]])[0]

    from core.schemas.dfiq import DFIQBase
    from core.schemas.entity import Entity
    from core.schemas.indicator import Indicator

    id_to_class = {"entities": Entity, "indicators": Indicator, "dfiq": DFIQBase}

    # Fetch real yeti objects from Arango
    yeti_objects = []
    for meta, distance in zip(object_metadatas, distances):
        if len(yeti_objects) >= request.count:
            break
        if "id" not in meta or "collection" not in meta:
            continue
        cls = id_to_class.get(meta["collection"])
        if not cls:
            continue
        if enforce_acls and not user.has_permissions(
            meta.get("extended_id", ""), roles.Permission.READ
        ):
            continue
        obj = cls.get(meta["id"])
        if obj:
            obj_dict = obj.model_dump()
            obj_dict["semantic_score"] = round(1 - distance, 4)
            yeti_objects.append(obj_dict)

    return SemanticSearchResponse(results=yeti_objects, total=len(yeti_objects))
