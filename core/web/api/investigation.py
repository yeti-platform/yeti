import re
from datetime import datetime
from flask import request
from flask.ext.classy import route
from bson.json_util import loads

from core.helpers import iterify
from core import investigation
from core.web.api.crud import CrudApi, CrudSearchApi
from core.observables import Observable
from core.entities import Entity
from core.web.api.api import render
from core.web.helpers import get_object_or_404


class InvestigationSearch(CrudSearchApi):
    template = 'investigation_api.html'
    objectmanager = investigation.Investigation


class Investigation(CrudApi):
    objectmanager = investigation.Investigation

    @route("/add/<string:id>", methods=['POST'])
    def add(self, id):
        i = get_object_or_404(self.objectmanager, id=id)
        data = loads(request.data)
        i.add(iterify(data['links']), iterify(data['nodes']))

        return render(i.info())

    @route("/remove/<string:id>", methods=['POST'])
    def remove(self, id):
        i = get_object_or_404(self.objectmanager, id=id)
        data = loads(request.data)
        i.remove(iterify(data['links']), iterify(data['nodes']))

        return render(i.info())

    @route("/rename/<string:id>", methods=['POST'])
    def rename(self, id):
        i = get_object_or_404(self.objectmanager, id=id)
        i.modify(name=request.json['name'], updated=datetime.utcnow())

        return render("ok")

    @route("/nodesearch/<path:query>", methods=['GET'])
    def nodesearch(self, query):
        result = []

        query = re.compile("^{}".format(query), re.IGNORECASE)

        observables = Observable.objects(value=query).limit(5)
        entities = Entity.objects(name=query).limit(5)

        for results in [observables, entities]:
            for node in results:
                result.append(node.to_mongo())

        return render(result)
