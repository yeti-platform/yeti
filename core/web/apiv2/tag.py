import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.schemas.tag import DEFAULT_EXPIRATION_DAYS, Tag


# Request schemas
class NewRequest(BaseModel):
    name: str
    default_expiration_days: int = DEFAULT_EXPIRATION_DAYS
    produces: list[str] = []
    replaces: list[str] = []

class UpdateRequest(NewRequest):
    pass

class TagSearchRequest(BaseModel):
    name: str | None = None
    produces: list[str] = []
    replaces: list[str] = []
    count: int
    page: int


# API endpoints
router = APIRouter()

@router.post('/')
async def new(request: NewRequest) -> Tag:
    """Creates a new observable in the database."""
    tag = Tag(
        name=request.name,
        default_expiration=datetime.timedelta(days=request.default_expiration_days),
        created=datetime.datetime.now(datetime.timezone.utc),
        produces=request.produces,
        replaces=request.replaces)
    new = tag.save()
    return new

@router.get('/{tag_id}')
async def details(tag_id) -> Tag:
    """Returns details about a Tag."""
    tag = Tag.get(tag_id)
    if not tag:
        raise HTTPException(
            status_code=404, detail=f"Tag {tag_id} not found")
    return tag

@router.put('/{tag_id}')
async def update(tag_id, request: UpdateRequest) -> Tag:
    """Updates an observable."""
    tag = Tag.get(tag_id)
    if not tag:
        raise HTTPException(status_code=404, detail="Item not found")

    tag.name = request.name
    tag.produces = request.produces
    tag.replaces = request.replaces
    tag.default_expiration = datetime.timedelta(days=request.default_expiration_days)
    tag = tag.save()
    return tag

@router.post('/search')
async def search(request: TagSearchRequest) -> list[Tag]:
    """Searches for Tags."""
    request_args = request.dict(exclude_unset=True)
    count = request_args.pop('count')
    page = request_args.pop('page')
    tag = Tag.filter(request_args, offset=page*count, count=count)
    return tag
