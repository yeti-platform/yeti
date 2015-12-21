from flask import request
from flask_restful import Resource
from flask_restful import abort as restful_abort
from mongoengine.errors import DoesNotExist

from core.web.api.api import render


class CrudApi(Resource):

    def get(self, id=None):
        if id:
            data = self.objectmanager.objects.get(id=id).info()
        else:
            data = [d.info() for d in self.objectmanager.objects.all()]

        return render(data, template=self.template)

    def post(self, id=None):
        print request.json
        if not id:
            return render(self.objectmanager.get_or_create(**request.json).info())
        else:
            self.objectmanager.update(id, request.json)

        return render({"status": "ok"})
