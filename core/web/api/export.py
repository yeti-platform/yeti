from flask import request
from flask_restful import abort as restful_abort

from core.web.api.crud import CrudApi
from core.export import Export, execute_export
from core.web.api.api import render


class ExportApi(CrudApi):
    template = "export_api.html"
    single_template = "export_api_single.html"
    objectmanager = Export

    def get(self, id=None, output=False):
        if id:
            data = self.objectmanager.objects.get(id=id).info()
        else:
            data = [d.info() for d in self.objectmanager.objects.all()]

        return render(data, template=self.template)

    def post(self, id=None, action=None):

        # special actions
        if action:

            # special actions
            if action == "refresh":
                execute_export.delay(id)
                return render({"id": id})

            elif action == "toggle":
                e = Export.objects.get(id=id)
                e.enabled = not e.enabled
                e.save()
                return render({"id": id, "status": e.enabled})

            else:
                restful_abort(400, error="action must be either refresh or toggle")

        else:  # normal crud - se if we can make this DRY
            if not id:
                return render(self.objectmanager.get_or_create(**request.json).info())
            else:
                self.objectmanager.update(id, request.json)
