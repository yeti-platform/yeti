from __future__ import unicode_literals

from core import entities
from core.web.api.crud import CrudSearchApi, CrudApi
from core.web.helpers import get_queryset


class EntitySearch(CrudSearchApi):
    template = "entity_api.html"
    objectmanager = entities.Entity

    def search(self, query):
        fltr = query.get("filter", {})
        params = query.get("params", {})
        regex = params.pop("regex", False)
        ignorecase = params.pop("ignorecase", False)
        page = params.pop("page", 1) - 1
        rng = params.pop("range", 50)

        return list(
            get_queryset(self.objectmanager, fltr, regex, ignorecase, replace=False)[
                page * rng : (page + 1) * rng
            ]
        )


class Entity(CrudApi):
    template = "entity_api.html"
    objectmanager = entities.Entity
    subobjects = {
        "Actor": entities.Actor,
        "Campaign": entities.Campaign,
        "Company": entities.Company,
        "ExploitKit": entities.ExploitKit,
        "Exploit": entities.Exploit,
        "Malware": entities.Malware,
        "TTP": entities.TTP,
    }
