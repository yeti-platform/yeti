from flask import request
from flask_restful import abort as restful_abort

from core.web.api.crud import CrudApi
from core.exports import Export, execute_export
from core.web.api.api import render
from core.helpers import string_to_timedelta
from core.observables import Tag


class ExportApi(CrudApi):
    template = "export_api.html"
    template_single = "export_api_single.html"
    objectmanager = Export

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
            params = request.json
            params['frequency'] = string_to_timedelta(params.get('frequency', '1:00:00'))
            params['include_tags'] = [Tag.objects.get(name=name.strip()) for name in params['include_tags'].split(',') if name.strip()]
            params['exclude_tags'] = [Tag.objects.get(name=name.strip()) for name in params['exclude_tags'].split(',') if name.strip()]
            if not id:
                return render(self.objectmanager(**params).save().info())
            else:
                self.objectmanager.objects(id=id).update(**params)
