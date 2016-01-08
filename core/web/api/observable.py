from flask import request

from core.web.api.crud import CrudApi, CrudSearchApi
from core.observables import Observable
from core.web.api.api import render


class ObservableApi(CrudApi):
    objectmanager = Observable

    def post(self, id=None):
        if not id:
            return render(self.objectmanager.add_text(request.json['value']).to_mongo())
        else:
            obj = self.objectmanager.get(id)
            obj.clean_update(**request.json)

        return render({"status": "ok"})


class ObservableSearchApi(CrudSearchApi):
    template = 'observable_api.html'
    objectmanager = Observable
