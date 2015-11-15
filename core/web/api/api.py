from flask import Blueprint, request, jsonify
from flask_negotiate import consumes, produces

from core.entities import Entity
from core.observables import Observable
from core.indicators import Indicator

api = Blueprint('api', __name__)

@api.route("/")
def index():
    return "API-OK\n"

@api.route("/query", methods=["POST"])
# @consumes("application/json")
# @produces("application/json")
def query():
    q = request.json
    print q

    matches = {}
    unknown = []

    # ko = Observable.objects(value__in=q['observables'])
    # matches['known_observables'] = [o.value for o in ko]

    for o in q['observables']:
        matches[o] = {}
        for i in Indicator.objects():
            if i.match(o):
                for type, nodes in i.neighbors().items():
                    for l, node in nodes:
                        indicator = node.info()
                        if l.description:
                            indicator['description'] = l.description
                        indicator["entity"] = type
                        matches[o][i.name] = matches[o].get(i.name, []) + [indicator]
    print matches

    return jsonify({"matches": matches, "unknown": unknown})
