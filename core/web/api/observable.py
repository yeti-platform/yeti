from flask import request

from core.web.api.crud import CrudApi, CrudSearchApi
from core import observables
from core.web.api.api import render


class Observable(CrudApi):
    objectmanager = observables.Observable

    def post(self, id=None):
        params = request.json
        source = params.pop('source', None)
        tags = params.pop('tags', None)
        strict = bool(params.pop('strict', False))

        if not id:
            obj = self.objectmanager.add_text(request.json['value'])
        else:
            obj = self.objectmanager.objects.get(id=id)

        if source:
            obj.add_source(source)

        if tags:
            obj.tag(tags.split(','), strict)

        if params:
            obj.clean_update(**params)

        return render({"status": "ok"})


class ObservableSearch(CrudSearchApi):
    template = 'observable_api.html'
    objectmanager = observables.Observable
