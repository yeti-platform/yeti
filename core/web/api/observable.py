from flask import request

from core.web.api.crud import CrudApi, CrudSearchApi
from core.observables import Observable
from core.web.api.api import render


class ObservableApi(CrudApi):
    objectmanager = Observable

    def post(self, id=None):
        params = request.json
        source = params.pop('source', None)

        if not id:
            obj = self.objectmanager.add_text(request.json['value'])
        else:
            obj = self.objectmanager.get(id)

        if source:
            obj.add_source(source)

        if params:
            obj.clean_update(**params)

        return render({"status": "ok"})


class ObservableSearchApi(CrudSearchApi):
    template = 'observable_api.html'
    objectmanager = Observable
