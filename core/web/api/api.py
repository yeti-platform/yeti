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

    results = {}

    ko = Observable.objects(value__in=q['observables'])
    results['known_observables'] = [o for o in ko]

    results['matched_indicators'] = []
    for i in Indicator.objects():
        for o in q['observables']:
            print i, o
            if i.match(o):
                results['matched_indicators'].append(i.name)

    return jsonify(results)
