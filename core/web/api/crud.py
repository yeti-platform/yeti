import re

from flask import request, url_for
from flask_restful import Resource
from flask_restful import abort as restful_abort
from mongoengine.errors import InvalidQueryError

from core.web.api.api import render


class CrudSearchApi(Resource):

    def post(self):
        query = request.get_json(silent=True)
        fltr = query.get('filter', {})
        params = query.get('params', {})

        regex = params.pop('regex', False)
        if regex:
            fltr = {key: re.compile(value) for key, value in fltr.items()}
        page = params.pop('page', 1) - 1
        rng = params.pop('range', 50)

        print "Filter:", fltr
        for key, value in fltr.copy().items():
            if key == 'tags':
                if not regex:
                    fltr['tags__name__in'] = fltr.pop('tags').split(',')
                else:
                    fltr['tags__name'] = fltr.pop('tags')

        try:
            data = []
            for o in self.objectmanager.objects(**fltr)[page * rng:(page + 1) * rng]:
                info = o.info()
                info['uri'] = url_for("api.{}".format(self.__class__.__name__.lower()), id=str(o.id))
                data.append(info)

        except InvalidQueryError as e:
            restful_abort(400, invalid_query=str(e))

        return render(data, self.template)


class CrudApi(Resource):

    def delete(self, id):
        obj = self.objectmanager.objects.get(id=id)
        obj.delete()
        return render({"status": "ok"})

    def get(self, id=None, template=None):
        if id:
            data = self.objectmanager.objects.get(id=id).info()
        else:
            data = [d.info() for d in self.objectmanager.objects.all()]

        if not template:  # template has not been overridden in URL
            if not id:  # determine if we're listing or displaying a single object
                template = self.template
            else:
                template = self.template_single

        return render(data, template=template)

    def post(self, id=None):
        if not id:
            return render(self.objectmanager(**request.json).save().info())
        else:
            self.objectmanager.update(id, request.json)

        return render({"status": "ok"})
