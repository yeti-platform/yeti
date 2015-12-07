import re

from flask import Blueprint, request
from flask_restful import Resource, Api
from flask_restful import abort as restful_abort
from flask.ext.negotiation import Render
from flask.ext.negotiation.renderers import renderer, template_renderer
from bson.json_util import dumps
from mongoengine import *
from mongoengine.errors import InvalidQueryError

from core.indicators import Indicator
from core.entities import Entity
from core.observables import Observable
from core.errors import ObservableValidationError

api = Blueprint("api", __name__, template_folder="templates")
api_restful = Api(api)


@renderer('application/json')
def bson_renderer(data, template=None, ctx=None):
    return dumps(data)

render = Render(renderers=[template_renderer, bson_renderer])


class AnalysisApi(Resource):

    def match_observables(self, observables):
        data = {"matches": [], "unknown": set(observables), "entities": [], "known": []}
        added_entities = set()

        for o, i in Indicator.search(observables):
            o = Observable.objects.get(value=o)
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
            data["unknown"].remove(o.value)

        for o in data["unknown"].copy():
            try:
                data["known"].append(Observable.objects.get(value=o).info())
                data["unknown"].remove(o)
            except DoesNotExist:
                continue

        return data

    def post(self):
        q = request.get_json(silent=True)

        # Save observables & eventual tags to database
        observables = []
        for value in q["observables"]:
            try:
                o = Observable.add_text(value)
            except ObservableValidationError:
                continue
            if q["observables"][value]["tags"]:
                o.tag(q["observables"][value]["tags"])
            observables.append(o)

        # match observables with known indicators
        data = self.match_observables(q["observables"])

        # find related observables (eg. URLs for domain, etc.)
        # related_observables = [obs.get_related() for obs in observables]
        # data = self.match_observables(related_observable)
        #
        # we need to find a way to degrade the "confidence" in
        # hits obtained from related observables

        return render(data, "observables.html")

api_restful.add_resource(AnalysisApi, '/analysis/')


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
        query = request.get_json(silent=True)
        fltr = query['filter']
        params = query['params']

        if params.pop('regex', False):
            fltr = {key: re.compile(value) for key, value in fltr.items()}

        print fltr

        try:
            data = [o.info() for o in Observable.objects(**fltr)]
        except InvalidQueryError as e:
            restful_abort(400, invalid_query=str(e))

        return render(data, 'observables.html')

api_restful.add_resource(ObservableApi, '/observables/')
