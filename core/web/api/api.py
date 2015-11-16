from flask import Blueprint, request
from flask_restful import Resource, Api
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

    def get(self):
        data = []
        for o in Observable.objects():
            data.append(o.info())
        return render(data)

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
        data = {"matches": [], "unknown": []}
        q = request.json
        for o in q["observables"]:
            found = False
            for i in Indicator.objects():
                if i.match(o):
                    found = True
                    match = i.info()
                    match['observable'] = o
                    match['related'] = []
                    for type, nodes in i.neighbors().items():
                        for l, node in nodes:
                            node_data = node.info()
                            if l.description:
                                node_data["link_description"] = l.description
                            else:
                                node_data["link_description"] = l.tag
                            node_data["entity"] = type
                            match['related'].append(node_data)
                    data["matches"].append(match)

            if not found:
                data["unknown"].append({"observable": o})

        return render(data, "observables.html")

api_restful.add_resource(ObservableApi, '/observables/')
