from __future__ import unicode_literals

from flask_classy import route
from flask import request, url_for

from core.web.api.crud import CrudApi, CrudSearchApi
from core import observables
from core.web.api.api import render
from core.web.helpers import get_object_or_404
from core.helpers import refang


class Observable(CrudApi):
    objectmanager = observables.Observable

    def _modify_observable(self, observable, params={}):
        source = params.pop('source', None)
        context = params.pop('context', None)
        tags = params.pop('tags', None)
        strict = bool(params.pop('strict', False))

        if source:
            observable.add_source(source)
        if context:
            observable.add_context(context)
        if tags is not None:
            observable.tag(tags, strict)
        if params:
            observable.clean_update(**params)

        info = observable.info()
        info['uri'] = url_for("api.{}:post".format(self.__class__.__name__), id=str(observable.id))
        return info

    @route("/", methods=["POST"])
    def new(self):
        """Create a new Observable

        Create a new Observable from the JSON object passed in the ``POST`` data.

        :<json object params: JSON object containing fields to set
        :<json boolean refang: If set, the observable will be refanged before being added to the database

        """
        params = request.json
        if params.pop('refang', None):
            obs = self.objectmanager.add_text(refang(params.pop('value')))
        else:
            obs = self.objectmanager.add_text(params.pop('value'))
        return render(self._modify_observable(obs, params))

    @route("/bulk", methods=["POST"])
    def bulk(self):
        """Bulk-add observables

        Bulk-add Observables from an array of strings.

        :<json [String] observables: Array of Strings representing observables (URLs, IPs, hostnames, etc.)
        :<json boolean refang: If set, the observables will be refanged before being added to the database
        """
        added = []
        params = request.json
        observables = params.pop('observables', [])
        for item in observables:
            if params.pop('refang', None):
                obs = self.objectmanager.add_text(refang(item))
            else:
                obs = self.objectmanager.add_text(item)

            added.append(self._modify_observable(obs, params.copy()))
        return render(added)

    @route("/<id>/context", methods=["POST"])
    def context(self, id):
        """Add context to an observable

        :<json object context: Context JSON to be added. Must include a ``source`` key.
        :<json string old_source: String defining the source to be replaced.
        :>json object: The context object that was actually added
        """
        observable = get_object_or_404(self.objectmanager, id=id)
        context = request.json.pop('context', {})
        old_source = request.json.pop('old_source', None)
        observable.add_context(context, replace_source=old_source)
        return render(context)

    @route("/<id>/context", methods=["DELETE"])
    def remove_context(self, id):
        """Removes context from an observable

        :<json object context: Context JSON to be added. Must include a ``source`` key.
        :>json object: The context object that was actually delete
        """
        observable = get_object_or_404(self.objectmanager, id=id)
        context = request.json.pop('context', {})
        observable.remove_context(context)
        return render(context)

    def post(self, id):
        obs = self.objectmanager.objects.get(id=id)
        return render(self._modify_observable(obs, request.json))

class ObservableSearch(CrudSearchApi):
    template = 'observable_api.html'
    objectmanager = observables.Observable
