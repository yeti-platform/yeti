from flask import request
from flask.ext.classy import route

from core.web.api.crud import CrudApi
from core.observables import Observable
from core.web.api.api import render
from core.analysis import match_observables


class Analysis(CrudApi):
    objectmanager = Observable

    @route("/match", methods=["POST"])
    def match(self):
        params = request.json
        observables = params.pop('observables', [])
        add_unknown = bool(params.pop('add_unknown', False))

        if add_unknown:
            for o in observables:
                Observable.add_text(o)

        data = match_observables(observables, save_matches=add_unknown)

        return render(data)
