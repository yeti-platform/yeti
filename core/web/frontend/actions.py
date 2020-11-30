import json
from os import path
from uuid import uuid4
from tempfile import gettempdir
from flask import request, send_file
from werkzeug.datastructures import MultiDict
from flask_classy import FlaskView, route

from core.exports import ExportTemplate
from core.observables import Observable
from core.web.helpers import requires_permissions, get_object_or_404, get_queryset


class ActionsView(FlaskView):
    def _get_selected_observables(self, data):
        if isinstance(data, MultiDict):
            ids = data.getlist("ids")
            query = data.get("query")
        else:
            ids = data.get("ids", None)
            query = data.get("query", None)

        if ids:
            return Observable.objects(id__in=ids)
        elif query:
            query = json.loads(query)
            fltr = query.get("filter", {})
            params = query.get("params", {})
            regex = params.pop("regex", False)
            ignorecase = params.pop("ignorecase", False)

            return get_queryset(Observable, fltr, regex, ignorecase)
        else:
            return []

    def _manage_tags(self, method):
        data = request.get_json(force=True)

        for observable in self._get_selected_observables(data):
            getattr(observable, method)(data["tags"])

        return ("", 200)

    @requires_permissions("tag", "observable")
    @route("/tag", methods=["POST"])
    def tag(self):
        return self._manage_tags("tag")

    @requires_permissions("tag", "observable")
    @route("/untag", methods=["POST"])
    def untag(self):
        return self._manage_tags("untag")

    @requires_permissions("read", "observable")
    @route("/export", methods=["POST"])
    def export(self):
        template = get_object_or_404(ExportTemplate, id=request.form["template"])

        filepath = path.join(gettempdir(), "yeti_{}.txt".format(uuid4()))
        template.render(self._get_selected_observables(request.form), filepath)

        return send_file(filepath, as_attachment=True)
