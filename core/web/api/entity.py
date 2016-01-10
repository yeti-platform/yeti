from core.web.api.crud import CrudSearchApi, CrudApi
from core.entities import Entity


class EntitySearchApi(CrudSearchApi):
    template = 'entity_api.html'
    objectmanager = Entity


class EntityApi(CrudApi):
    template = 'entity_api.html'
    objectmanager = Entity
