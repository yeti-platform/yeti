from flask import Blueprint, request
from flask_restful import Resource, Api, reqparse
from flask.ext.negotiation import Render
from flask.ext.negotiation.renderers import renderer, template_renderer, json_renderer
from bson.json_util import dumps, loads

from core.indicators import Indicator
from core.entities import Entity
from core.observables import Observable

api = Blueprint("api", __name__, template_folder="templates")
api_restful = Api(api)


@renderer('application/json')
def bson_renderer(data, template=None, ctx=None):
    return dumps(data)

render = Render(renderers=[template_renderer, bson_renderer])


class ObservableApi(Resource):

    def put(self):
        q = request.json
        data = {"count": 0}
        for o in q["observables"]:
            obs = Observable.add_text(o["value"])
            if "tags" in o:
                obs.tag(o["tags"])
            if "context" in o:
                obs.add_context(o["context"])
            data["count"] += 1

        return render(data)

    def post(self):
        q = request.json

        for o in q['observables']:
            pass


    def get(self):

        # try to get json body
        q = request.get_json(silent=True)

        if not q:  # if no json body is present, return list of all observables
            data = []
            for o in Observable.objects():
                data.append(o.info())
            return render(data)
        else:
            data = {"matches": [], "known": [], "unknown": [], "entities": []}
            added_entities = set()
            for o in q['observables']:
                indicator_match = False
                for i in Indicator.objects():
                    if i.match(o):
                        indicator_match = True
                        match = i.info()
                        match['observable'] = o
                        match['related'] = []
                        for _type, nodes in i.neighbors().items():
                            for l, node in nodes:

                                # add node name and link description to indicator
                                node_data = {"entity": _type, "name": node.name}
                                if l.description:
                                    node_data["link_description"] = l.description
                                else:
                                    node_data["link_description"] = l.tag
                                match["related"].append(node_data)

                                # uniquely add node information to related
                                # entitites
                                if node.name not in added_entities:
                                    nodeinfo = node.info()
                                    nodeinfo['nodetype'] = node.nodetype
                                    data["entities"].append(nodeinfo)
                                    added_entities.add(node.name)
                        data["matches"].append(match)

                if not indicator_match:
                    obs = Observable.objects(value=o)
                    if obs:
                        data['known'].append(obs[0].info())
                    else:
                        data["unknown"].append({"observable": o})

            return render(data, "observables.html")

api_restful.add_resource(ObservableApi, '/observables/')
