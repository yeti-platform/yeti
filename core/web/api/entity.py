from core.web.api.crud import CrudSearchApi
from core.entities import Entity


class EntityApi(CrudSearchApi):
    template = 'entity_api.html'
    objectmanager = Entity
