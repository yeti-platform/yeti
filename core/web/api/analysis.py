from __future__ import unicode_literals

from flask import request
from flask_classy import route
from flask_login import current_user

from core.web.api.crud import CrudApi
from core.observables import Observable
from core.errors import ObservableValidationError

from core.web.api.api import render
from core.analysis import match_observables
from core.web.helpers import requires_permissions


class Analysis(CrudApi):
    objectmanager = Observable

    @route("/match", methods=["POST"])
    @requires_permissions("read")
    def match(self):
        """Match observables against Yeti's intelligence repository.

        Takes an array of observables, expands them and tries to match them against specific indicators or known observables.

        To "expand" an observable means to enrich the query. For instance, if the arrays of observables contains the URL ``http://google.com``,
        the "expanded" observable array will also include the hostname ``google.com``.

        :<json [string] observables: An array of observables to be analyzed

        :>json [Entity] entities: Related ``Entity`` objects
        :>json [Observable] known: ``Observable`` objects that are already present in database
        :>json [Indicator] matches: ``Indicators`` that matched observables
        :>json Observable matches[].observable: The ``Observable`` object that matched the ``Indicator``
        :>json string unknown: Array of observable strings that didn't match any ``Indicators`` and are unknown to Yeti
        """

        params = request.json
        observables = params.pop('observables', [])
        fetch_neighbors = params.pop('fetch_neighbors', True)
        add_unknown = bool(params.pop('add_unknown', False))
        unknown = set()

        if add_unknown and current_user.has_permission('observable', 'write'):
            for o in observables:
                try:
                    Observable.add_text(o)
                except ObservableValidationError:
                    unknown.add(o)

        data = match_observables(
            observables,
            save_matches=add_unknown and
            current_user.has_permission('observable', 'write'),
            fetch_neighbors=fetch_neighbors)

        data['unknown'] = list(set(data['unknown']) | unknown)

        return render(data)
