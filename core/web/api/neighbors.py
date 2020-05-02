from __future__ import unicode_literals

from flask import request
from flask_classy import route

from core.entities import Entity, Malware, TTP, Actor, ExploitKit, Exploit, \
    Campaign
from core.indicators import Indicator, Yara, Regex
from core.observables import Observable
from core.web.api.api import render
from core.web.api.crud import CrudApi
from core.web.helpers import requires_permissions

NODES_CLASSES = {
    'entity': Entity,
    'observable': Observable,
    'indicator': Indicator,
    'malware': Malware,
    'ttp': TTP,
    'actor': Actor,
    'campaign': Campaign,
    'exploit': Exploit,
    'exploitkit': ExploitKit,
    'regex': Regex,
    'yara': Yara,
}


class Neighbors(CrudApi):

    @requires_permissions('read')
    def get(self, klass, node_id):
        klass = NODES_CLASSES[klass.lower().split('.')[0]]
        node = klass.objects.get(id=node_id)

        result = {'links': list(), 'nodes': list()}

        result['nodes'].append(node.to_mongo())

        node_ids = set()
        links = list(set(list(node.incoming()) + list(node.outgoing())))

        for link, node in links:
            if node.id not in node_ids:
                node_ids.add(node)
                result['nodes'].append(node.to_mongo())

            result['links'].append(link.to_dict())

        return render(result)

    @route("/tuples/<klass>/<node_id>/<type_filter>", methods=["POST"])
    @requires_permissions('read')
    def tuples(self, klass, node_id, type_filter):
        query = request.get_json(silent=True) or {}
        fltr = query.get("filter", {})
        params = query.get("params", {})

        klass = NODES_CLASSES[klass.lower().split('.')[0]]
        filter_class = NODES_CLASSES[type_filter.lower().split('.')[0]]
        node = klass.objects.get(id=node_id)

        regex = bool(params.pop('regex', False))
        ignorecase = bool(params.pop('ignorecase', False))
        page = int(params.pop("page", 1)) - 1
        rng = int(params.pop("range", 50))

        print("[{}] Filter: {}".format(self.__class__.__name__, fltr))
        print(filter_class, fltr, regex, ignorecase, page, rng)
        neighbors = node.neighbors_advanced(
            filter_class, fltr, regex, ignorecase, page, rng)

        _all = []
        links = []
        objs = []

        for link, obj in neighbors:
            links.append(link)
            objs.append(obj)
            _all.append((link, obj))

        data = {"objs": objs, "links": links}
        if issubclass(filter_class, Entity):
            return render(data, template='entity_api.html')
        if issubclass(filter_class, Indicator):
            return render(data, template='indicator_api.html')
        if issubclass(filter_class, Observable):
            return render(data, template='observable_api.html')

    @route("/tuples/<klass>/<node_id>/<type_filter>/total", methods=["GET"])
    @requires_permissions('read')
    def total(self, klass, node_id, type_filter):
        query = request.get_json(silent=True) or {}
        fltr = query.get("filter", {})
        params = query.get("params", {})

        klass = NODES_CLASSES[klass.lower().split('.')[0]]
        filter_class = NODES_CLASSES[type_filter.lower().split('.')[0]]
        node = klass.objects.get(id=node_id)

        regex = bool(params.pop('regex', False))
        ignorecase = bool(params.pop('ignorecase', False))

        return render({
            'total': node.neighbors_total(filter_class, fltr, regex, ignorecase)
        })
