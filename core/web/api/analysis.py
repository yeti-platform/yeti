from flask import request
from flask_restful import Resource

from mongoengine.errors import DoesNotExist

from core.observables import Observable
from core.indicators import Indicator
from core.web.api.api import render
from core.errors import ObservableValidationError


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
        for obs in q["observables"]:
            try:
                o = Observable.add_text(obs['value'])
            except ObservableValidationError:
                continue
            if obs.get("tags", []):
                o.tag(o["tags"])
            observables.append(o)

        # match observables with known indicators
        data = self.match_observables([o['value'] for o in q["observables"]])

        # find related observables (eg. URLs for domain, etc.)
        # related_observables = [obs.get_related() for obs in observables]
        # data = self.match_observables(related_observable)
        #
        # we need to find a way to degrade the "confidence" in
        # hits obtained from related observables

        return render(data, "observables.html")
