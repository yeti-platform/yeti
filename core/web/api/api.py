from flask import Blueprint, request, jsonify
from flask_negotiate import consumes, produces

from core.entities import Entity
from core.observables import Observable
from core.indicators import Indicator

api = Blueprint('api', __name__)


@api.route("/")
def index():
    return "API-OK\n"


@api.route("/observables", methods=["POST"])
# @consumes("application/json")
# @produces("application/json")
def observables():
    q = request.json

    matches = {}
    for o in q['observables']:
        matches[o] = {}
        for i in Indicator.objects():
            if i.match(o):
                for type, nodes in i.neighbors().items():
                    for l, node in nodes:
                        indicator = node.info()
                        if l.description:
                            indicator['link_description'] = l.description
                        else:
                            indicator['link_description'] = l.tag
                        indicator["entity"] = type
                        matches[o][i.name] = matches[o].get(i.name, []) + [indicator]

    return jsonify({"matches": matches})
