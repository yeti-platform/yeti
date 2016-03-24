import re
import logging

from flask import request, url_for, abort
from flask.ext.classy import FlaskView, route
from mongoengine.errors import InvalidQueryError

from core.web.api.api import render


class CrudSearchApi(FlaskView):

    def search(self, query):
        fltr = query.get('filter', {})
        if 'tags' in fltr:
            fltr["tags__name"] = fltr.pop('tags')
        fltr = {key.replace(".", "__")+"__all": value for key, value in query.get('filter', {}).items()}
        params = query.get('params', {})

        regex = params.pop('regex', False)
        if regex:
            fltr = {key: [re.compile(v) for v in value] for key, value in fltr.items()}

        page = params.pop('page', 1) - 1
        rng = params.pop('range', 50)

        print "[{}] Filter: {}".format(self.__class__.__name__, fltr)

        data = []
        for o in self.objectmanager.objects(**fltr)[page * rng:(page + 1) * rng]:
            o.uri = url_for("api.{}:post".format(self.objectmanager.__name__), id=str(o.id))
            data.append(o)

        return data


    def post(self):
        query = request.get_json(silent=True) or {}

        try:
            data = self.search(query)
        except InvalidQueryError as e:
            logging.error(e)
            abort(400)

        return render(data, self.template)


class CrudApi(FlaskView):

    template = None
    template_single = None

    def delete(self, id):
        obj = self.objectmanager.objects.get(id=id)
        obj.delete()
        return render({"status": "ok"})

    def index(self):
        data = []
        for obj in self.objectmanager.objects.all():
            obj.uri = url_for("api.{}:get".format(self.__class__.__name__), id=str(obj.id))
            data.append(obj)
        return render(data, template=self.template)

    # This method can be overridden if needed
    def _parse_request(self, json):
        return json

    def get(self, id):
        obj = self.objectmanager.objects.get(id=id)
        obj.uri = url_for("api.{}:post".format(self.__class__.__name__), id=str(obj.id))
        return render(obj, self.template_single)

    @route("/", methods=["POST"])
    def new(self):
        params = self._parse_request(request.json)
        obj = self.objectmanager(**params).save()
        obj.uri = url_for("api.{}:post".format(self.__class__.__name__), id=str(obj.id))
        return render(obj)

    def post(self, id):
        obj = self.objectmanager.objects.get(id=id)
        params = self._parse_request(request.json)
        obj = obj.clean_update(**params)
        obj.uri = url_for("api.{}:post".format(self.__class__.__name__), id=str(obj.id))
        return render(obj)
