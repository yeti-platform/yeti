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
    return SearchResponse(results=results, total=total)
