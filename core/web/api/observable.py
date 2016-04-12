from flask.ext.classy import route
from flask import request, url_for

from core.web.api.crud import CrudApi, CrudSearchApi
from core import observables
from core.web.api.api import render


class Observable(CrudApi):
    objectmanager = observables.Observable

    def _modify_observable(self, observable, params={}):
        source = params.pop('source', None)
        tags = params.pop('tags', None)
        strict = bool(params.pop('strict', False))

        if source:
            observable.add_source(source)
        if tags is not None:
            observable.tag(tags, strict)
        if params:
            observable.clean_update(**params)

        info = observable.info()
        info['uri'] = url_for("api.{}:post".format(self.__class__.__name__), id=str(observable.id))
        return info

    @route("/", methods=["POST"])
    def new(self):
        params = request.json
        obs = self.objectmanager.add_text(params.pop('value'))
        return render(self._modify_observable(obs, params))

    @route("/bulk", methods=["POST"])
    def bulk(self):
        added = []
        params = request.json
        observables = params.pop('observables', [])
        for item in observables:
            obs = self.objectmanager.add_text(item)
            added.append(self._modify_observable(obs, params))
        return render(added)

    def post(self, id):
        obs = self.objectmanager.objects.get(id=id)
        return render(self._modify_observable(obs, request.json))

class ObservableSearch(CrudSearchApi):
    template = 'observable_api.html'
    objectmanager = observables.Observable
