from flask_restful import Resource

from core.web.api.api import render


class CrudApi(Resource):

    def get(self, id=None):
        if id:
            data = self.objectmanager.objects.get(id=id).info()
        else:
            data = [d.info() for d in self.objectmanager.objects.all()]

        return render(data, template=self.template)
