from flask import request
from flask_restful import Resource

from core.observables import Observable, Url, Hostname
from core.indicators import Indicator
from core.web.api.api import render
from core.errors import ObservableValidationError
from core.helpers import del_from_set

# load analyzers
from plugins.analytics.process_hostnames import ProcessHostnames
from plugins.analytics.process_url import ProcessUrl

analyzers = {
    Hostname: [ProcessHostnames],
    Url: [ProcessUrl],
}

def derive(observables):
    if isinstance(observables, (str, unicode)):
        observables = [observables]

    new = []
    for observable in observables:
        try:
            t = Observable.guess_type(observable)
            for a in analyzers.get(t, []):
                new.extend([n for n in a.analyze_string(observable) if n and n not in observables])
        except ObservableValidationError:
            pass

    if len(new) == 0:
        return observables
    else:
        return derive(new + observables)


def match_observables(observables):
    # Remove empty observables
    observables = [observable for observable in observables if observable]
    extended_query = set(observables) | set(derive(observables))
    added_entities = set()

    data = {"matches": [], "unknown": set(observables), "entities": [], "known": [], "neighbors": []}

    for o in Observable.objects(value__in=list(extended_query)):
        data['known'].append(o.info())
        del_from_set(data['unknown'], o.value)

        for link, node in (o.incoming()):
            if isinstance(node, Observable):
                if (link.src.value not in extended_query or link.dst.value not in extended_query) and node.tags:
                    data['neighbors'].append((link.info(), node.info()))

    for o, i in Indicator.search(extended_query):
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
        del_from_set(data["unknown"], o.value)

    return data
