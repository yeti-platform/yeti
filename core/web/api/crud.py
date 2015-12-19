from flask_restful import Resource

from core.web.api.api import render


class CrudApi(Resource):

    @classmethod
    def get(cls, id=None):
        if id:
            data = cls.objectmanager.objects.get(id=id).info()
        else:
            data = [d.info() for d in cls.objectmanager.objects.all()]

        return render(data, template=cls.template)
