import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.schemas.template import Template
from core import taskmanager

# Request schemas
class TemplateSearchRequest(BaseModel):
    name: str = ''
    count: int = 50
    page: int = 0

class TemplateSearchResponse(BaseModel):
    templates: list[Template]
    total: int

class PatchTemplateRequest(BaseModel):
    template: Template

# API endpoints
router = APIRouter()

@router.post('/')
async def new(request: PatchTemplateRequest) -> Template:
    """Creates a new template."""
    # TODO: Validate template
    return request.template.save()

@router.patch('/{template_id}')
async def update(template_id: str, request: PatchTemplateRequest) -> Template:
    """Updates a template."""
    db_template = Template.get(template_id)
    if not db_template:
        raise HTTPException(status_code=404, detail=f'Template {template_id} not found.')
    update_data = request.template.dict(exclude_unset=True)
    updated_template = db_template.copy(update=update_data)
    new = updated_template.save()
    return new

@router.post('/search')
async def search(request: TemplateSearchRequest) -> TemplateSearchResponse:
    """Searches for observables."""
    request_args = request.dict(exclude={'count', 'page'})
    templates, total = Template.filter(request_args, offset=request.page*request.count, count=request.count)
    return TemplateSearchResponse(templates=templates, total=total)

@router.delete('/{template_id}')
async def delete(template_id: str):
    """Deletes a template from the database."""
    template = Template.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f'Template {template_id} not found.')
    template.delete()
