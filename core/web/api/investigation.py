from flask import request

from core.helpers import iterify
from core.investigation import Investigation
from core.web.api.crud import CrudApi
from core.web.api.api import render
from core.web.helpers import get_object_or_404, find_method


class InvestigationApi(CrudApi):
    objectmanager = Investigation

    def post(self, id=None, action=None):
        if id is None or action is None:
            return super(InvestigationApi, self).post(id)
        else:
            method = find_method(self, action, 'action')
            investigation = get_object_or_404(Investigation, id=id)

            return method(investigation)

    def add(self, investigation):
        investigation.add(iterify(request.json['links']), iterify(request.json['nodes']))

        return render(investigation.info())
