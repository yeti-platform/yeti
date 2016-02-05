from flask import request
from flask.ext.classy import route

from core.web.api.crud import CrudApi
# from core.exports import Export, execute_export, ExportTemplate
from core import exports
from core.web.api.api import render
from core.helpers import string_to_timedelta
from core.observables import Tag

class ExportTemplate(CrudApi):
    template = "export_template_api"
    objectmanager = exports.ExportTemplate

class Export(CrudApi):
    template = "export_api.html"
    template_single = "export_api_single.html"
    objectmanager = exports.Export

    @route("/<string:id>/refresh", methods=["POST"])
    def refresh(self, id):
        exports.execute_export.delay(id)
        return render({"id": id})

    @route("/<string:id>/toggle", methods=["POST"])
    def toggle(self, id):
        e = self.objectmanager.objects.get(id=id)
        e.enabled = not e.enabled
        e.save()
        return render({"id": id, "status": e.enabled})

    def parse_request(self, json):
        params = json
        params['frequency'] = string_to_timedelta(params.get('frequency', '1:00:00'))
        params['include_tags'] = [Tag.objects.get(name=name.strip()) for name in params['include_tags'].split(',') if name.strip()]
        params['exclude_tags'] = [Tag.objects.get(name=name.strip()) for name in params['exclude_tags'].split(',') if name.strip()]
        params['template'] = exports.ExportTemplate.objects.get(name=params['template'])
        return params
