from __future__ import unicode_literals

from core import entities
from core.web.api.crud import CrudSearchApi, CrudApi
from core.web.helpers import get_queryset


class EntitySearch(CrudSearchApi):
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
    objectmanager = entities.Entity
    subobjects = {
        "actor": entities.Actor,
        "campaign": entities.Campaign,
        "company": entities.Company,
        "exploitkit": entities.ExploitKit,
        "exploit": entities.Exploit,
        "malware": entities.Malware,
        "ttp": entities.TTP,
    }
