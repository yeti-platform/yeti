from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from core.database_arango import ArangoYetiConnector

# API endpoints
router = APIRouter()


class SearchRequest(BaseModel):
    """Global search request message."""

    model_config = ConfigDict(extra="forbid")

    query: str
    count_per_type: int = Field(default=5, ge=1)


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
    # ChromaDB rejects a non-positive n_results, so an unconstrained count
    # turns a client mistake into a server error. Reject it at the boundary.
    count: int = Field(default=10, ge=1)
    root_type: Literal["entity", "indicator", "dfiq"] | None = None


class SemanticSearchResponse(BaseModel):
    """Semantic Search Response, bucketed by type like grouped exact-match
    search: each type gets its own independently-bounded slice of nearest
    neighbors, so results from one type can't crowd another out of a
    shared page. `total` here is just how many were returned for that
    type (not a corpus-wide count) -- ANN search doesn't have a cheap way
    to count "everything within the top-K" beyond what was fetched."""

    sections: list[SearchResultSection]


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


SEMANTIC_TYPE_TO_COLLECTION = {
    "entity": "entities",
    "indicator": "indicators",
    "dfiq": "dfiq",
}


def _similarity_score(distance: float) -> float:
    """Converts a ChromaDB distance into a 0-1 similarity, 1 being identical.

    The collection uses ChromaDB's default `l2` space, so `distance` is a
    *squared* euclidean distance, and the default embedding function returns
    unit-length vectors. For unit vectors ||a-b||^2 == 2 - 2*cos(a, b), which
    inverts to the cosine similarity below and bounds the raw distance to
    [0, 4].

    Cosine similarity is itself [-1, 1], so this clamps to [0, 1]. The
    negative half only occurs for anti-correlated embeddings, which for text
    means nothing more specific than "unrelated" -- the same thing 0 already
    conveys -- so clamping loses no usable signal and gives clients a scale
    they can threshold on directly.
    """
    cosine_similarity = 1 - (distance / 2)
    return round(max(0.0, min(1.0, cosine_similarity)), 4)


def _semantic_search_one_type(
    collection, query: str, count: int, collection_name: str, cls, user, enforce_acls
) -> SearchResultSection:
    """Queries ChromaDB for nearest neighbors within a single type's
    collection (via a metadata filter), so this type's results are bounded
    independently of how many candidates other types produce -- mirrors
    grouped_search's per-type isolation, just as a separate Chroma query
    per type instead of one AQL query fanning out, since Chroma's ANN
    index doesn't support per-group limits within a single query.
    """
    from core.schemas import roles

    # Two things shrink the candidate list after the nearest-neighbour search:
    # ACL filtering, and rolling several documents belonging to one object back
    # into a single result. Overfetch to absorb both and still have a shot at
    # `count` results -- not a guarantee: if visibility is narrow enough, or one
    # object dominates the window with many of its own documents, fewer than
    # `count` can still come back.
    fetch_count = count * 3 if enforce_acls else count * 2
    results = collection.query(
        query_texts=[query],
        n_results=fetch_count,
        where={"collection": collection_name},
    )

    object_metadatas = results.get("metadatas", [[]])[0]
    # ChromaDB returns nearest (most similar) first. See _similarity_score for
    # what the raw distance means and how it's converted.
    distances = results.get("distances", [[]])[0]

    yeti_objects = []
    seen_objects = set()
    for meta, distance in zip(object_metadatas, distances):
        if len(yeti_objects) >= count:
            break
        if "id" not in meta:
            continue
        # An object is indexed as several documents (its own text, plus one per
        # DFIQ approach), any of which can match. Results are already ordered
        # best-first, so the first document seen for an object is its best one
        # and the rest are dropped -- the object is what's being returned, not
        # the document that happened to match.
        extended_id = meta.get("extended_id", "")
        if extended_id in seen_objects:
            continue
        if enforce_acls and not user.has_permissions(
            extended_id, roles.Permission.READ
        ):
            continue
        obj = cls.get(meta["id"])
        if obj:
            seen_objects.add(extended_id)
            obj_dict = obj.model_dump()
            obj_dict["semantic_score"] = _similarity_score(distance)
            # Which document matched: "self" for the object's own text, or
            # "approach:N". Useful for explaining *why* something was returned.
            obj_dict["matched_on"] = meta.get("chunk", "self")
            yeti_objects.append(obj_dict)

    type_name = next(
        t for t, c in SEMANTIC_TYPE_TO_COLLECTION.items() if c == collection_name
    )
    return SearchResultSection(
        type=type_name, results=yeti_objects, total=len(yeti_objects)
    )


@router.post("/semantic")
def semantic_search(
    httpreq: Request, request: SemanticSearchRequest
) -> SemanticSearchResponse:
    """Performs a semantic search on Yeti objects, bucketed by type.

    Results come from a nearest-neighbor lookup in ChromaDB, which knows
    nothing about ACLs, so each candidate is checked individually against
    the calling user's permissions before being returned. Pass root_type
    to scope the search to just one type (e.g. "dfiq" for investigative
    guidance rather than threat data); omit it to search every indexed
    type, each independently bounded to `count`.
    """
    from core.chromadb_client import get_semantic_collection
    from core.schemas import rbac, roles
    from core.schemas.dfiq import DFIQBase
    from core.schemas.entity import Entity
    from core.schemas.indicator import Indicator

    collection = get_semantic_collection()

    user = httpreq.state.user
    enforce_acls = rbac.RBAC_ENABLED and not user.admin

    id_to_class = {"entities": Entity, "indicators": Indicator, "dfiq": DFIQBase}
    types_to_query = (
        [request.root_type] if request.root_type else list(SEMANTIC_TYPE_TO_COLLECTION)
    )

    sections = [
        _semantic_search_one_type(
            collection,
            request.query,
            request.count,
            SEMANTIC_TYPE_TO_COLLECTION[type_name],
            id_to_class[SEMANTIC_TYPE_TO_COLLECTION[type_name]],
            user,
            enforce_acls,
        )
        for type_name in types_to_query
    ]

    return SemanticSearchResponse(sections=sections)
