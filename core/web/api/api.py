from flask import Blueprint, request, jsonify, render_template
from flask.ext.negotiation import Render
from flask.ext.negotiation.renderers import renderer, template_renderer, json_renderer

from core.entities import Entity
from core.observables import Observable
from core.indicators import Indicator

api = Blueprint("api", __name__, template_folder="templates")

render = Render(renderers=[template_renderer, json_renderer])


@api.route("/")
def index():
    return "API-OK\n"


@api.route("/observables/", methods=["POST"])
def observables():
    q = request.json

    data = {"matches": [], "unknown": []}

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
