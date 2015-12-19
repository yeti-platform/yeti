import re

from flask import request, url_for
from flask_restful import Resource
from flask_restful import abort as restful_abort
from mongoengine.errors import InvalidQueryError

from core.web.api.api import render


class CrudApi(Resource):

    @classmethod
    def put(cls):
        q = request.json
        data = {"count": 0}
        for o in q["observables"]:
            obs = cls.add_text(o["value"])
            if "tags" in o:
                obs.tag(o["tags"])
            if "context" in o:
                obs.add_context(o["context"])
            data["count"] += 1

        return render(data)

    @classmethod
    def get(cls, id=None):
        if id:
            data = cls.objectmanager.objects.get(id=id).info()
        else:
            data = [d.info() for d in cls.objectmanager.objects.all()]

        return render(data, template=cls.template)

    @classmethod
    def post(cls):
        query = request.get_json(silent=True)
        fltr = query.get('filter', {})
        params = query.get('params', {})

        if params.pop('regex', False):
            fltr = {key: re.compile(value) for key, value in fltr.items()}
        page = params.pop('page', 1) - 1
        rng = params.pop('range', 50)

        print "Filter:", fltr

        try:
            data = []
            for o in cls.objectmanager.objects(**fltr)[page * rng:(page + 1) * rng]:
                info = o.info()
                info['uri'] = url_for("api.{}".format(cls.__name__.lower()), id=str(o.id))
                data.append(info)

        except InvalidQueryError as e:
            restful_abort(400, invalid_query=str(e))

        return render(data, cls.template)
