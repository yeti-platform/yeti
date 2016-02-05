from flask.ext.classy import route
from flask import request, url_for

from core.web.api.crud import CrudApi, CrudSearchApi
from core import observables
from core.web.api.api import render


class Observable(CrudApi):
    objectmanager = observables.Observable

    def modify_observable(self, observable):
        params = request.json
        source = params.pop('source', None)
        tags = params.pop('tags', None)
        strict = bool(params.pop('strict', False))

        if source:
            observable.add_source(source)
        if tags is not None:
            observable.tag(tags.split(','), strict)
        if params:
            observable.clean_update(**params)

        info = observable.info()
        info['uri'] = url_for("api.{}:post".format(self.__class__.__name__), id=str(observable.id))
        return render(info)

    @route("/", methods=["POST"])
    def new(self):
        obs = self.objectmanager.add_text(request.json['value'])
        return self.modify_observable(obs)

    def post(self, id):
        obs = self.objectmanager.objects.get(id=id)
        return self.modify_observable(obs)

class ObservableSearch(CrudSearchApi):
    template = 'observable_api.html'
    objectmanager = observables.Observable
