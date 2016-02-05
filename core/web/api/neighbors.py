from core.web.api.api import render_json
from core.web.api.crud import CrudApi
from core.entities import Entity
from core.observables import Observable
from core.indicators import Indicator

NODES_CLASSES = {
    'entity': Entity,
    'observable': Observable,
    'indicator': Indicator,
}


class Neighbors(CrudApi):

    def get(self, klass, node_id):
        klass = NODES_CLASSES[klass.lower().split('.')[0]]
        node = klass.objects.get(id=node_id)

        result = {
            'links': list(),
            'nodes': list()
        }

        node_ids = set()
        links = list(set(node.incoming() + node.outgoing()))

        for link, node in links:
            if node.id not in node_ids:
                node_ids.add(node)
                result['nodes'].append(node.to_mongo())

            result['links'].append(link.to_dict())

        return render_json(result)
