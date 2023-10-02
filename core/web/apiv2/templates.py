import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, Field

from core.schemas.template import Template
from core.schemas.observable import Observable

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

class RenderExportRequest(BaseModel):
    template_id: str
    observable_ids: list[str] | None = None
    search_query: str | None = None

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
    update_data = request.template.model_dump(exclude_unset=True)
    updated_template = db_template.model_copy(update=update_data)
    new = updated_template.save()
    return new

@router.post('/search')
async def search(request: TemplateSearchRequest) -> TemplateSearchResponse:
    """Searches for observables."""
    request_args = request.model_dump(exclude={'count', 'page'})
    templates, total = Template.filter(request_args, offset=request.page*request.count, count=request.count)
    return TemplateSearchResponse(templates=templates, total=total)

@router.post('/render')
async def render(request: RenderExportRequest) -> StreamingResponse:
    """Renders a template."""
    if not request.search_query and not request.observable_ids:
        raise HTTPException(status_code=400, detail='Must specify either search_query or observable_ids.')

    template = Template.get(request.template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f'Template {request.template_id} not found.')

    if request.search_query:
        observables, _ = Observable.filter({'value': request.search_query})
        if not observables:
            raise HTTPException(status_code=404, detail=f'No observables found for search query.')
    else:
        observables = [Observable.get(observable_id) for observable_id in request.observable_ids]
    data = template.render_raw(observables)
    def _stream():
        for d in data.split('\n'):
            yield d + '\n'
    return StreamingResponse(_stream(), media_type='text/plain', headers={'Content-Disposition': f'attachment; filename={template.name}.txt'})


@router.delete('/{template_id}')
async def delete(template_id: str):
    """Deletes a template from the database."""
    template = Template.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f'Template {template_id} not found.')
    template.delete()
