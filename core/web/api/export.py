from __future__ import unicode_literals

import os

from flask import send_from_directory, make_response
from flask_classy import route
from mongoengine.errors import DoesNotExist

from core.web.api.crud import CrudApi
from core import exports
from core.web.api.api import render
from core.helpers import string_to_timedelta
from core.observables import Tag
from core.web.helpers import requires_role, requires_permissions


class ExportTemplate(CrudApi):
    template = "export_template_api"
    objectmanager = exports.ExportTemplate


class Export(CrudApi):
    template = "export_api.html"
    template_single = "export_api_single.html"
    objectmanager = exports.Export

    @route("/<string:id>/content")
    @requires_permissions('read')
    def content(self, id):
        """Return export content

        Returns a given export's content.

        :query ObjectID id: Export ID
        :resheader X-Yeti-Export-MD5: The MD5 hash of the exported content. Use it to check the export's integrity
        """
        try:
            e = self.objectmanager.objects.get(id=id)
        except DoesNotExist:
            return render({"error": "No Export found for id {}".format(id)}), 404
        if e.output_dir.startswith("/"):
            d = e.output_dir
        else:
            d = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), e.output_dir)

        response = make_response(send_from_directory(d, e.name, as_attachment=True, attachment_filename=e.name))
        response.headers['X-Yeti-Export-MD5'] = e.hash_md5
        return response

    @route("/<string:id>/refresh", methods=["POST"])
    @requires_permissions('refresh')
    def refresh(self, id):
        """Refresh an export

        Manually executes an export if it is not already exporting.

        :query ObjectID id: Export ID
        :>json ObjectID id: The export's ObjectID
        """
        exports.execute_export.delay(id)
        return render({"id": id})

    @route("/<string:id>/toggle", methods=["POST"])
    @requires_permissions('toggle')
    def toggle(self, id):
        """Toggle an export

        Toggles an export. A deactivated export will not execute when called (manually or scheduled)

        :query ObjectID id: Export ID
        :>json ObjectID id: The export's ObjectID
        :>json boolean status: The result of the toggle operation (``true`` means the export has been enabled, ``false`` means it has been disabled)
        """
        e = self.objectmanager.objects.get(id=id)
        e.enabled = not e.enabled
        e.save()
        return render({"id": id, "status": e.enabled})

    def _parse_request(self, json):
        params = json
        params['frequency'] = string_to_timedelta(params.get('frequency', '1:00:00'))
        params['ignore_tags'] = [Tag.objects.get(name=name.strip()) for name in params['ignore_tags'].split(',') if name.strip()]
        params['include_tags'] = [Tag.objects.get(name=name.strip()) for name in params['include_tags'].split(',') if name.strip()]
        params['exclude_tags'] = [Tag.objects.get(name=name.strip()) for name in params['exclude_tags'].split(',') if name.strip()]
        params['template'] = exports.ExportTemplate.objects.get(name=params['template'])
        return params
