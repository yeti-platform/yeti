from __future__ import unicode_literals

import re
from datetime import datetime
from flask import request
from flask_classy import route
from bson.json_util import loads
from bson.objectid import ObjectId

from core.helpers import iterify
from core import investigation
from core.web.api.crud import CrudApi, CrudSearchApi
from core.observables import *
from core.investigation import ImportResults
from core.entities import Entity
from core.web.api.api import render, render_json
from core.web.helpers import get_object_or_404
from core.web.helpers import requires_permissions, get_queryset


class InvestigationSearch(CrudSearchApi):
    template = 'investigation_api.html'
    objectmanager = investigation.Investigation

    def search(self, query):
        fltr = query.get('filter', {})
        params = query.get('params', {})
        regex = params.pop('regex', False)
        ignorecase = params.pop('ignorecase', False)
        page = params.pop('page', 1) - 1
        rng = params.pop('range', 50)

        return list(
            get_queryset(
                self.objectmanager, fltr, regex, ignorecase,
                replace=False)[page * rng:(page + 1) * rng])


class Investigation(CrudApi):
    objectmanager = investigation.Investigation

    @route("/add/<string:id>", methods=['POST'])
    @requires_permissions('write')
    def add(self, id):
        i = get_object_or_404(self.objectmanager, id=id)
        data = loads(request.data)
        i.add(iterify(data['links']), iterify(data['nodes']))

        return render(i.info())

    @route("/remove/<string:id>", methods=['POST'])
    @requires_permissions('write')
    def remove(self, id):
        i = get_object_or_404(self.objectmanager, id=id)
        data = loads(request.data)
        i.remove(iterify(data['links']), iterify(data['nodes']))

        return render(i.info())

    @route("/rename/<string:id>", methods=['POST'])
    @requires_permissions('write')
    def rename(self, id):
        i = get_object_or_404(self.objectmanager, id=id)
        i.modify(name=request.json['name'], updated=datetime.utcnow())

        return render("ok")

    @route("/nodesearch/<path:query>", methods=['GET'])
    @requires_permissions('read')
    def nodesearch(self, query):
        result = []

        query = re.compile("^{}".format(query), re.IGNORECASE)

        observables = Observable.objects(value=query).limit(5)
        entities = Entity.objects(name=query).limit(5)

        for results in [observables, entities]:
            for node in results:
                result.append(node.to_mongo())

        return render(result)

    @route('/import_results/<string:id>')
    @requires_permissions('read')
    def import_results(self, id):
        results = get_object_or_404(ImportResults, id=id)

        return render(results.to_mongo())

    @route('/bulk_add/<string:id>', methods=['POST'])
    @requires_permissions('write')
    def bulk_add(self, id):
        i = get_object_or_404(self.objectmanager, id=id)
        data = loads(request.data)
        nodes = []

        response = {'status': 'ok', 'message': ''}

        try:
            for node in data['nodes']:
                if node['type'] in globals() and issubclass(
                        globals()[node['type']], Observable):
                    _type = globals()[node['type']]

                n = _type.get_or_create(value=node['value'])
                if node['new_tags']:
                    n.tag(node['new_tags'].split(', '))
                nodes.append(n)

            i.add([], nodes)
        except Exception, e:
            response = {'status': 'error', 'message': str(e)}

        return render(response)

    @route('/search_existence', methods=["POST"])
    @requires_permissions('read')
    def search_existence(self):
        """Query investigation based on given observable, incident or entity

            Query[ref]: class of the given node, which should be observable or entity
            Query[id]: the id of the given node.

        """
        REF_CLASS = ('observable', 'entity')

        data = loads(request.data)

        if 'id' not in data or 'ref' not in data:
            response = {
                'status': 'error',
                'message': 'missing argument.'
            }

        elif not ObjectId.is_valid(data['id']):
            response = {
                'status': 'error',
                'message': 'given id is not valid.'
            }

        elif data['ref'] not in REF_CLASS:
            response = {
                'status': 'error',
                'message': 'reference class is not valid.'
            }

        else:
            query = {
                'nodes': {
                    '$elemMatch': {
                        '$id': ObjectId(data['id']),
                        '$ref': data['ref']
                    }
                },
            }
            response = self.objectmanager.objects(__raw__=query).order_by('-updated')
            for inv in response:
                if not inv.name:
                    inv['name'] = 'Unnamed Investigation'

        return render(response)
