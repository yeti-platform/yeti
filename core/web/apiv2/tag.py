import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from core.schemas.tag import DEFAULT_EXPIRATION, Tag


# Request schemas
class NewRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    name: str
    default_expiration: datetime.timedelta = DEFAULT_EXPIRATION
    produces: list[str] = []
    replaces: list[str] = []


class UpdateRequest(NewRequest):
    model_config = ConfigDict(extra='forbid')

    pass


class TagSearchRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    name: str | None = None
    produces: list[str] = []
    replaces: list[str] = []
    count: int
    page: int


class TagSearchResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    tags: list[Tag]
    total: int


class MergeTagRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    merge: list[str]
    merge_into: str
    permanent: bool = False


class MergeTagResult(BaseModel):
    model_config = ConfigDict(extra='forbid')

    merged: int
    into: Tag


# API endpoints
router = APIRouter()


@router.post("/")
async def new(request: NewRequest) -> Tag:
    """Creates a new observable in the database."""
    tag = Tag(
        name=request.name,
        default_expiration=request.default_expiration,
        created=datetime.datetime.now(datetime.timezone.utc),
        produces=request.produces,
        replaces=request.replaces,
    )
    new = tag.save()
    return new


@router.get("/{tag_id}")
async def details(tag_id: str) -> Tag:
    """Returns details about a Tag."""
    tag = Tag.get(tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail=f"Tag {tag_id} not found")
    return tag


@router.put("/{tag_id}")
async def update(tag_id: str, request: UpdateRequest) -> Tag:
    """Updates an observable."""
    tag = Tag.get(tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail="Item not found")

    tag.name = request.name
    tag.produces = request.produces
    tag.replaces = request.replaces
    tag.default_expiration = request.default_expiration
    tag = tag.save()
    return tag


@router.post("/search")
async def search(request: TagSearchRequest) -> TagSearchResponse:
    """Searches for Tags."""
    request_args = request.model_dump(exclude_unset=True)
    count = request_args.pop("count")
    page = request_args.pop("page")
    tags, total = Tag.filter(request_args, offset=page * count, count=count)
    return TagSearchResponse(tags=tags, total=total)


@router.delete("/{tag_id}")
async def delete(tag_id: str) -> None:
    """Deletes a Tag."""
    tag = Tag.get(tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail="Tag ID {tag_id} not found")
    tag.delete()


@router.post("/merge")
async def merge(request: MergeTagRequest) -> MergeTagResult:
    target_tag = Tag.find(name=request.merge_into)
    if not target_tag:
        raise HTTPException(
            status_code=404, detail=f"Tag '{request.merge_into}' not found"
        )

    if request.merge_into in request.merge:
        raise HTTPException(status_code=400, detail="Cannot merge a tag into itself")

    merged = target_tag.absorb(request.merge, request.permanent)
    return MergeTagResult(merged=merged, into=target_tag)
