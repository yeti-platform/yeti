import re

from flask import request, url_for
from flask.ext.classy import FlaskView, route
from flask_restful import abort as restful_abort
from mongoengine.errors import InvalidQueryError

from core.web.api.api import render


class CrudSearchApi(FlaskView):

    def post(self):
        query = request.get_json(silent=True) or {}
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
                info['uri'] = url_for("api.{}:post".format(self.__class__.__name__), id=str(o.id))
                data.append(info)

        except InvalidQueryError as e:
            restful_abort(400, invalid_query=str(e))

        return render(data, self.template)


class CrudApi(FlaskView):

    template = None
    template_single = None

    def delete(self, id):
        obj = self.objectmanager.objects.get(id=id)
        obj.delete()
        return render({"status": "ok"})

    # @route('/')
    def index(self):
        data = []
        for obj in self.objectmanager.objects.all():
            info = obj.info()
            info['uri'] = url_for("api.{}:get".format(self.__class__.__name__), id=str(obj.id))
            data.append(info)

        return render(data, template=self.template)


    def delete(self, id):
        obj = self.objectmanager.objects.get(id=id)
        obj.delete()
        return render({"status": "ok"})


    # This method can be overridden if needed
    def parse_request(self, json):
        return json

    def get(self, id):
        data = self.objectmanager.objects.get(id=id).info()
        return render(data, self.template_single)

    @route("/", methods=["POST"])
    def new(self):
        params = self.parse_request(request.json)
        return render(self.objectmanager(**params).save().info())

    def post(self, id):
        obj = self.objectmanager.objects.get(id=id)
        params = self.parse_request(request.json)
        obj.clean_update(**params)
        return render({"status": "ok"})
