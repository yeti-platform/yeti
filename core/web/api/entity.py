from __future__ import unicode_literals

from core import entities
from core.web.api.crud import CrudSearchApi, CrudApi


class EntitySearch(CrudSearchApi):
    template = 'entity_api.html'
    objectmanager = entities.Entity


class Entity(CrudApi):
    template = 'entity_api.html'
    objectmanager = entities.Entity
