from core.web.api.crud import CrudApi
from core.export import Export, execute_export
from core.web.api.api import render


class ExportApi(CrudApi):
    template = "export_api.html"
    objectmanager = Export

    def get(cls, id=None, output=False):
        if id:
            data = cls.objectmanager.objects.get(id=id).info()
        else:
            data = [d.info() for d in cls.objectmanager.objects.all()]

        return render(data, template=cls.template)

    def post(self, name, action):
        if action == "refresh":
            execute_export.delay(name)
            return render({"name": name})
        elif action == "toggle":
            f = Export.objects.get(name=name)
            f.enabled = not f.enabled
            f.save()
            return render({"name": name, "status": f.enabled})
