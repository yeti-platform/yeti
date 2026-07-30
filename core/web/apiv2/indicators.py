import logging
from typing import Annotated, cast

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from core import errors
from core.schemas import audit, model, rbac, roles
from core.schemas.indicator import (
    ForensicArtifact,
    Indicator,
    IndicatorType,
    IndicatorTypes,
    IndicatorTypesRuntime,
    Yara,
)
from core.schemas.tag import MAX_TAGS_REQUEST

from . import context, crud, tagging

logger = logging.getLogger(__name__)


# Request schemas
class NewIndicatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: IndicatorTypesRuntime = Field(discriminator="type")


class PatchIndicatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicator: IndicatorTypesRuntime = Field(discriminator="type")


class IndicatorSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: dict[str, str | int | list] = {}
    type: IndicatorType | None = None
    sorting: list[tuple[str, bool]] = []
    filter_aliases: list[tuple[str, str]] = []
    count: int = 50
    page: int = 0


class IndicatorMultipleGetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    names: list[str] = []
    type: IndicatorType | None = None
    sorting: list[tuple[str, bool]] = []
    filter_aliases: list[tuple[str, str]] = []
    count: int = 50
    page: int = 0


class IndicatorSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    indicators: list[IndicatorTypesRuntime]
    total: int


class IndicatorTagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[str]
    tags: Annotated[list[str], Field(max_length=MAX_TAGS_REQUEST)] = []
    strict: bool = False


class IndicatorTagResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tagged: int
    tags: dict[str, dict[str, model.YetiTagInstance]]


class YaraBundleRequest(BaseModel):
    """Request to generate a YARA bundle from a list of indicators.

    Attributes:
        ids: List of YARA IDs to include in the bundle.
        tags: List of tags to include in the bundle.
        exclude_tags: List of tags to exclude from the bundle.
        overlays: Set of overlay names to apply to the bundle. Over
    """

    model_config = ConfigDict(extra="forbid")

    ids: list[str] = []
    tags: list[str] = []
    exclude_tags: list[str] = []
    overlays: set[str] = set()


class YaraBundleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle: str


# API endpoints
router = APIRouter()


@router.post("/")
@rbac.global_permission(roles.Permission.WRITE)
def new(httpreq: Request, request: NewIndicatorRequest) -> IndicatorTypesRuntime:
    """Creates a new indicator in the database."""
    try:
        new = request.indicator.save()
    except errors.ObjectCreationError as error:
        raise HTTPException(
            status_code=400, detail={"meta": error.meta, "description": str(error)}
        )

    rbac.set_acls(new, user=httpreq.state.user)
    audit.log_timeline(httpreq.state.username, new)
    return new


@router.patch("/{id}")
@rbac.permission_on_target(roles.Permission.WRITE)
def patch(
    httpreq: Request, request: PatchIndicatorRequest, id: str
) -> IndicatorTypesRuntime:
    """Modifies an indicator in the database."""
    db_indicator = Indicator.get(id)
    if not db_indicator:
        raise HTTPException(status_code=404, detail=f"Indicator {id} not found")

    if db_indicator.type == IndicatorType.forensicartifact:
        if db_indicator.pattern != request.indicator.pattern:
            return ForensicArtifact.from_yaml_string(request.indicator.pattern)[0]

    db_indicator.get_tags()
    update_data = request.indicator.model_dump(exclude_unset=True)
    updated_indicator = db_indicator.model_copy(update=update_data)
    new = cast("IndicatorTypes", updated_indicator.save())

    if new.type == IndicatorType.forensicartifact:
        new.update_yaml()
        new = new.save()

    audit.log_timeline(httpreq.state.username, new, old=db_indicator)
    new.get_acls()
    return new


@router.post("/{id}/context")
@rbac.permission_on_target(roles.Permission.WRITE)
def add_context(
    httpreq: Request, id: str, request: context.AddContextRequest
) -> IndicatorTypesRuntime:
    """Adds context to an indicator."""
    return context.add_context(Indicator, httpreq, id, request)


@router.put("/{id}/context")
@rbac.permission_on_target(roles.Permission.WRITE)
def replace_context(
    httpreq: Request, id: str, request: context.ReplaceContextRequest
) -> IndicatorTypesRuntime:
    """Replaces context in an indicator."""
    return context.replace_context(Indicator, httpreq, id, request)


@router.post("/{id}/context/delete")
@rbac.permission_on_target(roles.Permission.WRITE)
def delete_context(
    httpreq: Request, id, request: context.DeleteContextRequest
) -> IndicatorTypesRuntime:
    """Removes context to an indicator."""
    return context.delete_context(Indicator, httpreq, id, request)


@router.get("/")
def get(
    httpreq: Request,
    name: str,
    type: IndicatorType | None = None,
) -> IndicatorTypesRuntime:
    """Gets an indicator by name."""
    params = {"name": name}
    if type:
        params["type"] = type
    return crud.get_by_lookup(
        Indicator,
        httpreq,
        params,
        f"Indicator {name} not found (type: {type or 'any'})",
    )


@router.get("/{id}")
@rbac.permission_on_target(roles.Permission.READ)
def details(httpreq: Request, id: str) -> IndicatorTypesRuntime:
    """Returns details about an indicator."""
    return crud.get_details(Indicator, id, "indicator not found")


@router.delete("/{id}")
@rbac.permission_on_target(roles.Permission.DELETE)
def delete(httpreq: Request, id: str) -> None:
    """Deletes an indicator."""
    crud.delete_object(Indicator, httpreq, id, f"Indicator ID {id} not found")


@router.post("/search")
def search(
    httpreq: Request, request: IndicatorSearchRequest
) -> IndicatorSearchResponse:
    """Searches for indicators."""
    query = request.query
    if request.type:
        query["type"] = request.type
    indicators, total = Indicator.filter(
        query_args=query,
        offset=request.page * request.count,
        count=request.count,
        sorting=request.sorting,
        aliases=request.filter_aliases,
        user=httpreq.state.user,
    )
    return IndicatorSearchResponse(indicators=indicators, total=total)


@router.post("/get/multiple")
def get_multiple(
    httpreq: Request, request: IndicatorMultipleGetRequest
) -> IndicatorSearchResponse:
    """Gets multiple indicators by name."""
    query = {"name__in": request.names}
    if request.type:
        query["type"] = request.type
    indicators, total = Indicator.filter(
        query_args=query,
        offset=request.page * request.count,
        count=request.count,
        sorting=request.sorting,
        aliases=request.filter_aliases,
        user=httpreq.state.user,
    )
    return IndicatorSearchResponse(indicators=indicators, total=total)


@router.post("/tag")
@rbac.permission_on_ids(roles.Permission.WRITE)
def tag(httpreq: Request, request: IndicatorTagRequest) -> IndicatorTagResponse:
    """Tags entities."""
    tagged, tags = tagging.tag_objects(
        Indicator,
        httpreq,
        request.ids,
        request.tags,
        request.strict,
        not_found_status_code=404,
        not_found_detail=(
            lambda iid: f"Tagging request contained an unknown indicator: ID:{iid}"
        ),
    )
    return IndicatorTagResponse(tagged=tagged, tags=tags)


@router.post("/yara/bundle")
def get_yara_bundle(httpreq: Request, request: YaraBundleRequest) -> YaraBundleResponse:
    """Generates a YARA bundle from a list of indicators."""
    yaras = []

    seen_ids = set()

    for yara_id in request.ids:
        db_yara = Yara.get(yara_id)
        if not db_yara:
            raise HTTPException(
                status_code=404,
                detail=f"YARA bundle request contained an unknown Yara: ID:{yara_id}",
            )
        if any(tag.name in request.exclude_tags for tag in db_yara.tags):
            continue
        yaras.append(db_yara)
        seen_ids.add(db_yara.id)

    if request.tags:
        yara_from_tags, _ = Indicator.filter(
            query_args={"type": "yara", "tags": request.tags},
            user=httpreq.state.user,
        )

        for yara in yara_from_tags:
            if yara.id in seen_ids:
                continue
            if any(tag.name in request.exclude_tags for tag in yara.tags):
                continue
            yaras.append(yara)

    bundle = Yara.generate_yara_bundle(rules=cast("list[Yara]", yaras))

    if request.overlays:
        yara_map = {}
        for yara in yaras:
            yara_map[yara.name] = yara

        bundle = Yara.render_with_overlays(bundle, yara_map, request.overlays)

    return YaraBundleResponse(bundle=bundle)
