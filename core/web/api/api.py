from flask import Blueprint, request
from flask_restful import Resource, Api
from flask.ext.negotiation import Render
from flask.ext.negotiation.renderers import renderer, template_renderer
from bson.json_util import dumps

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

    def get(self):
        return render([o.info() for o in Observable.objects()])

    def post(self):
        q = request.get_json(silent=True)
        data = {"matches": [], "known": [], "unknown": set(q["observables"]), "entities": []}
        added_entities = set()

        for o, i in Indicator.search(q["observables"]):
            # observables matching indicators are probably worth keeping
            # save automatically
            o = Observable.add_text(o)
            
            match = i.info()
            match.update({"observable": o.info(), "related": [], "suggested_tags": set()})

            for nodes in i.neighbors().values():
                for l, node in nodes:
                    # add node name and link description to indicator
                    node_data = {"entity": node.type, "name": node.name, "link_description": l.description or l.tag}
                    match["related"].append(node_data)

                    # uniquely add node information to related entitites
                    if node.name not in added_entities:
                        nodeinfo = node.info()
                        nodeinfo['type'] = node.type
                        data["entities"].append(nodeinfo)
                        added_entities.add(node.name)

                    o_tags = o.get_tags()
                    [match["suggested_tags"].add(tag) for tag in node.generate_tags() if tag not in o_tags]

            data["matches"].append(match)

        for o in list(data["unknown"]):
            try:
                data["known"].append(Observable.objects.get(value=o).info())
                data["unknown"].remove(o)
            except Exception as e:
                pass

        return render(data, "observables.html")

api_restful.add_resource(ObservableApi, '/observables/')
