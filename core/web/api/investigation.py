from flask import request
from flask.ext.classy import route
from bson.json_util import loads

from core.helpers import iterify
from core import investigation
from core.web.api.crud import CrudApi
from core.web.api.api import render
from core.web.helpers import get_object_or_404


class Investigation(CrudApi):
    objectmanager = investigation.Investigation

    @route("/add/<string:id>", methods=['POST'])
    def add(self, id):
        i = get_object_or_404(self.objectmanager, id=id)
        data = loads(request.data)
        i.add(iterify(data['links']), iterify(data['nodes']))

        return render(i.info())
