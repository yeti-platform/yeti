from flask import request
from flask.ext.classy import route

from core.helpers import iterify
from core.investigation import Investigation
from core.web.api.crud import CrudApi
from core.web.api.api import render
from core.web.helpers import get_object_or_404


class InvestigationApi(CrudApi):
    objectmanager = Investigation

    @route("/add/<string:id>", methods=['POST'])
    def add(self, id):
        investigation = get_object_or_404(Investigation, id=id)
        investigation.add(iterify(request.json['links']), iterify(request.json['nodes']))

        return render(investigation.info())
