from flask import request
from flask_restful import Resource

from mongoengine.errors import DoesNotExist

from core.observables import Observable
from core.indicators import Indicator
from core.web.api.api import render
from core.errors import ObservableValidationError


def match_observables(observables):
    data = {"matches": [], "unknown": set(observables), "entities": [], "known": []}
    added_entities = set()

    for o, i in Indicator.search(observables):
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
        data["known"].append(o.info())
        data["unknown"].remove(o.value)

    for o in data["unknown"].copy():
        try:
            data["known"].append(Observable.objects.get(value=o).info())
            data["unknown"].remove(o)
        except DoesNotExist:
            continue

    return data


class AnalysisApi(Resource):

    def post(self):
        q = request.get_json(silent=True)
        params = q.pop("params", {})
        observables = []

        for o in q["observables"]:
            try:
                obs = Observable.guess_type(o['value'])(value=o['value'])
                obs.clean()
                observables.append(obs.value)

                # Save observables & eventual tags to database
                if params.get('save_query', False):
                    obs = obs.save()
                    obs.tag(o.get("tags", []))
                    obs.add_source("query")
            except ObservableValidationError:
                continue

        # match observables with known indicators
        data = match_observables([o for o in observables])

        # find related observables (eg. URLs for domain, etc.)
        # related_observables = [obs.get_related() for obs in observables]
        # data = self.match_observables(related_observable)
        #
        # we need to find a way to degrade the "confidence" in
        # hits obtained from related observables

        return render(data, "analysis.html")
