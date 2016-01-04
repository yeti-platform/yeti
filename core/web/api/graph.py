from flask_restful import Resource

from core.web.api.api import render_json
from core.observables import Observable


class GraphNeighborsApi(Resource):
    def get(self, node_id):
        node = Observable.objects.get(id=node_id)

        result = {
            'links': list(),
            'nodes': list()
        }

        links = list(set(node.incoming() + node.outgoing()))

        for link, node in links:
            new_link = {
                'id': str(link.id),
                'from': str(link.src.id),
                'to': str(link.dst.id),
            }

            if link.description:
                new_link['label'] = link.description
            elif link.tag:
                new_link['tag'] = link.tag

            result['links'].append(new_link)
            result['nodes'].append(node.info())

        return render_json(result)
