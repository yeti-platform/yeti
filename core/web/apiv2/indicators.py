from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, conlist

from core.schemas import graph
from core.schemas.indicator import (
    ForensicArtifact,
    Indicator,
    IndicatorType,
    IndicatorTypes,
)
from core.schemas.tag import MAX_TAGS_REQUEST


# Request schemas
class NewIndicatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: IndicatorTypes = Field(discriminator="type")


class PatchIndicatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: IndicatorTypes = Field(discriminator="type")


class IndicatorSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: dict[str, str | int | list] = {}
    type: IndicatorType | None = None
    sorting: list[tuple[str, bool]] = []
    filter_aliases: list[tuple[str, str]] = []
    count: int = 50
    page: int = 0


class IndicatorSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicators: list[IndicatorTypes]
    total: int


class IndicatorTagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[str]
    tags: conlist(str, max_length=MAX_TAGS_REQUEST) = []
    strict: bool = False


class IndicatorTagResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tagged: int
    tags: dict[str, dict[str, graph.TagRelationship]]


# API endpoints
router = APIRouter()


@router.post("/")
async def new(request: NewIndicatorRequest) -> IndicatorTypes:
    """Creates a new indicator in the database."""
    new = request.indicator.save()
    return new


@router.patch("/{indicator_id}")
async def patch(request: PatchIndicatorRequest, indicator_id) -> IndicatorTypes:
    """Modifies an indicator in the database."""
    db_indicator: IndicatorTypes = Indicator.get(indicator_id)  # type: ignore
    if not db_indicator:
        raise HTTPException(
            status_code=404, detail=f"Indicator {indicator_id} not found"
        )

    if db_indicator.type == IndicatorType.forensicartifact:
        if db_indicator.pattern != request.indicator.pattern:
            return ForensicArtifact.from_yaml_string(request.indicator.pattern)[0]

    update_data = request.indicator.model_dump(exclude_unset=True)
    updated_indicator = db_indicator.model_copy(update=update_data)
    new = updated_indicator.save()

    if new.type == IndicatorType.forensicartifact:
        new.update_yaml()
        new = new.save()

    return new


@router.get("/{indicator_id}")
async def details(indicator_id) -> IndicatorTypes:
    """Returns details about an indicator."""
    db_indicator: IndicatorTypes = Indicator.get(indicator_id)  # type: ignore
    if not db_indicator:
        raise HTTPException(status_code=404, detail="indicator not found")
    db_indicator.get_tags()
    return db_indicator


@router.delete("/{indicator_id}")
async def delete(indicator_id: str) -> None:
    """Deletes an indicator."""
    db_indicator = Indicator.get(indicator_id)
    if not db_indicator:
        raise HTTPException(
            status_code=404, detail="Indicator ID {indicator_id} not found"
        )
    db_indicator.delete()


@router.post("/search")
async def search(request: IndicatorSearchRequest) -> IndicatorSearchResponse:
    """Searches for indicators."""
    query = request.query
    tags = query.pop("tags", [])
    if request.type:
        query["type"] = request.type
    indicators, total = Indicator.filter(
        query_args=query,
        tag_filter=tags,
        offset=request.page * request.count,
        count=request.count,
        sorting=request.sorting,
        aliases=request.filter_aliases,
        graph_queries=[("tags", "tagged", "outbound", "name")],
    )
    return IndicatorSearchResponse(indicators=indicators, total=total)


@router.post("/tag")
async def tag(request: IndicatorTagRequest) -> IndicatorTagResponse:
    """Tags entities."""
    indicators = []
    for indicator_id in request.ids:
        db_indicator = Indicator.get(indicator_id)
        if not db_indicator:
            raise HTTPException(
                status_code=404,
                detail=f"Tagging request contained an unknown indicator: ID:{indicator_id}",
            )
        indicators.append(db_indicator)

    indicator_tags = {}
    for db_indicator in indicators:
        db_indicator.tag(request.tags, strict=request.strict)
        indicator_tags[db_indicator.extended_id] = db_indicator.tags

    return IndicatorTagResponse(tagged=len(indicators), tags=indicator_tags)
