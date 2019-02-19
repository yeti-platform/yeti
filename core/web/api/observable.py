from __future__ import unicode_literals

import logging

from flask_classy import route
from flask import request, abort
from flask_login import current_user

from core.web.api.crud import CrudApi, CrudSearchApi
from core import observables
from core.web.api.api import render
from core.web.helpers import get_object_or_404
from core.helpers import refang
from core.web.helpers import requires_permissions
from core.errors import GenericYetiError, ObservableValidationError


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
        return info

    @route("/", methods=["POST"])
    @requires_permissions('write')
    def new(self):
        """Create a new Observable

        Create a new Observable from the JSON object passed in the ``POST`` data.

        :<json object params: JSON object containing fields to set
        :<json boolean refang: If set, the observable will be refanged before being added to the database
        """
        params = request.json

        if 'id' in params:
            obs = self.objectmanager.objects.get(id=params.pop("id"))
        else:
            forced_type = params.pop('force_type', None)
            try:
                if params.pop('refang', None):
                    obs = self.objectmanager.add_text(refang(params.pop('value')), force_type=forced_type)
                else:
                    obs = self.objectmanager.add_text(params.pop('value'), force_type=forced_type)
            except (GenericYetiError, ObservableValidationError) as e:
                logging.error(e)
                abort(400)

            return render(self._modify_observable(obs, params))

    @route("/bulk", methods=["POST"])
    @requires_permissions('write')
    def bulk(self):
        """Bulk-add observables

        Bulk-add Observables from an array of strings.

        :<json [{string: observable, tags: [string]}] observables: Array of Strings representing observables (URLs, IPs, hostnames, etc.)
        :<json boolean refang: If set, the observables will be refanged before being added to the database
        """
        added = []
        params = request.json
        bulk = params.pop('observables', [])
        _refang = params.pop('refang', False)
        for item in bulk:
            value = item['value']
            tags = item.get('tags', [])

            if _refang:
                obs = self.objectmanager.add_text(refang(value), tags)
            else:
                obs = self.objectmanager.add_text(value, tags)
            self._modify_observable(
                obs, {
                    'source': item.get('source'),
                    'context': item.get('context'),
                })
            added.append(obs)
        return render(added)

    @route("/<id>/context", methods=["POST"])
    @requires_permissions('read')
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
    @requires_permissions('write')
    def remove_context(self, id):
        """Removes context from an observable

        :<json object context: Context JSON to be added. Must include a ``source`` key.
        :>json object: The context object that was actually delete
        """
        observable = get_object_or_404(self.objectmanager, id=id)
        context = request.json.pop('context', {})
        observable.remove_context(context)
        return render(context)

    @requires_permissions('write')
    def post(self, id):
        obs = self.objectmanager.objects.get(id=id)
        j = request.json
        if not current_user.has_permission('observable', 'tag') and 'tags' in j:
            abort(401)
        return render(self._modify_observable(obs, request.json))


class ObservableSearch(CrudSearchApi):
    template = 'observable_api.html'
    objectmanager = observables.Observable
