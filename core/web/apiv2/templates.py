import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict

from core.config.config import yeti_config
from core.schemas.observable import Observable
from core.schemas.template import Template


# Request schemas
class TemplateSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = ""
    count: int = 50
    page: int = 0


class TemplateSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    templates: list[Template]
    total: int


# class PatchTemplateRequest(BaseModel):
#     model_config = ConfigDict(extra="forbid")

#     template: Template


class RenderTemplateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    template_name: str
    observable_ids: list[str] = []
    search_query: str | None = None


# API endpoints
router = APIRouter()

@router.post("/search")
async def search(request: TemplateSearchRequest) -> TemplateSearchResponse:
    """Searches for observables."""
    glob = "*"
    if request.name:
        glob = f'*{request.name}*'

    template_dir = yeti_config.get("system", "template_dir", "/opt/yeti/templates")
    files = []
    total = 0
    for file in Path(template_dir).rglob(f"{glob}.jinja2"):
        total += 1
        files.append(file)

    files = sorted(files)
    templates = []
    for file in files[(request.page*request.count):((request.page+1)*request.count)]:
        template = Template(name=file.stem, template=file.read_text())
        templates.append(template)

    return TemplateSearchResponse(templates=templates, total=total)


@router.post("/render")
async def render(request: RenderTemplateRequest) -> StreamingResponse:
    """Renders a template."""
    if not request.search_query and not request.observable_ids:
        raise HTTPException(
            status_code=400,
            detail="Must specify either search_query or observable_ids.",
        )

    template = Template.find(name=request.template_name)
    if not template:
        raise HTTPException(
            status_code=404, detail=f"Template {request.template_name} not found."
        )

    if request.search_query:
        observables, _ = Observable.filter({"value": request.search_query})
        if not observables:
            raise HTTPException(
                status_code=404, detail="No observables found for search query."
            )
    else:
        observables = []
        for observable_id in request.observable_ids:
            db_obs = Observable.get(observable_id)
            if not db_obs:
                logging.warning(
                    f"Observable with id {observable_id} not found, skipping..."
                )
                continue
            observables.append(db_obs)

    data = template.render(observables, None)

    def _stream():
        for d in data.split("\n"):
            yield d + "\n"

    return StreamingResponse(
        _stream(),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={template.name}.txt"},
    )
