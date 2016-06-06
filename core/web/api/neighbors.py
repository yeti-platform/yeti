from __future__ import unicode_literals

import re

from flask import url_for, request
from flask_classy import route

from core.web.api.api import render_json, render
from core.web.api.crud import CrudApi
from core.entities import Entity, Malware, TTP, Actor
from core.observables import Observable
from core.indicators import Indicator

NODES_CLASSES = {
    'entity': Entity,
    'observable': Observable,
    'indicator': Indicator,
    'malware': Malware,
    'ttp': TTP,
    'actor': Actor,
}


class Neighbors(CrudApi):

    def get(self, klass, node_id):
        klass = NODES_CLASSES[klass.lower().split('.')[0]]
        node = klass.objects.get(id=node_id)

        result = {
            'links': list(),
            'nodes': list()
        }

        result['nodes'].append(node.to_mongo())

        node_ids = set()
        links = list(set(node.incoming() + node.outgoing()))

        for link, node in links:
            if node.id not in node_ids:
                node_ids.add(node)
                result['nodes'].append(node.to_mongo())

            result['links'].append(link.to_dict())

        return render_json(result)

    @route("/tuples/<klass>/<node_id>/<type_filter>", methods=["POST"])
    def tuples(self, klass, node_id, type_filter):
        query = request.get_json(silent=True) or {}
        fltr = query.get("filter", {})
        params = query.get("params", {})

        klass = NODES_CLASSES[klass.lower().split('.')[0]]
        filter_class = NODES_CLASSES[type_filter.lower().split('.')[0]]
        node = klass.objects.get(id=node_id)

        # code taken from CrudSearchApi. See if we can replicate the inheritance here
        if 'tags' in fltr:
            fltr["tags__name"] = fltr.pop('tags')
        fltr = {key.replace(".", "__")+"__all": value for key, value in query.get('filter', {}).items()}
        regex = params.pop('regex', False)
        if regex:
            flags = 0
            if params.pop('ignorecase', False):
                flags |= re.I
            fltr = {key: [re.compile(v, flags=flags) for v in value] for key, value in fltr.items()}

        print "[{}] Filter: {}".format(self.__class__.__name__, fltr)
        # end of c/c code

        neighbors = node.neighbors_advanced(filter_class, params=params, filter=fltr)

        _all = []
        links = []
        objs = []

        for link, obj in neighbors:
            links.append(link)
            objs.append(obj)
            _all.append((link, obj))

        data = {"data": objs, "links": links}
        # First argument of render is the "data" variable in the template.
        # We override this behavior for these templates to include links
        # using the ctx argument
        if issubclass(filter_class, Entity):
            return render(data, template='entity_api.html', ctx=data)
        if issubclass(filter_class, Indicator):
            return render(data, template='indicator_api.html', ctx=data)
        if issubclass(filter_class, Observable):
            return render(data, template='observable_api.html', ctx=data)
