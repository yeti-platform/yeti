from __future__ import unicode_literals

from flask_classy import route
from flask import render_template, request, flash
from mongoengine import DoesNotExist

from core.web.frontend.generic import GenericView
from core.investigation import Investigation, ImportMethod
from core.web.helpers import get_object_or_404
from core.web.helpers import requires_permissions

from core.database import AttachedFile
from core.entities import Entity
from core.indicators import Indicator
from core.observables import Observable

from core.web.api.api import bson_renderer


class InvestigationView(GenericView):

    klass = Investigation

    @route("/graph/<id>")
    @requires_permissions("read", "investigation")
    def graph(self, id):
        investigation = get_object_or_404(Investigation, id=id)
        return render_template("{}/graph.html".format(self.klass.__name__.lower()), investigation=bson_renderer(investigation.info()))

    @route("/graph/<klass>/<id>")
    @requires_permissions("read", "investigation")
    def graph_node(self, klass, id):
        if klass == 'entity':
            node = get_object_or_404(Entity, id=id)
        elif klass == 'indicator':
            node = get_object_or_404(Indicator, id=id)
        else:
            node = get_object_or_404(Observable, id=id)

        investigation = Investigation().save()
        investigation.add([], [node])

        return render_template("{}/graph.html".format(self.klass.__name__.lower()), investigation=bson_renderer(investigation.info()))

    @route("/import", methods=['GET', 'POST'])
    def inv_import(self):
        if request.method == "GET":
            return render_template("{}/import.html".format(self.klass.__name__.lower()))
        else:
            file = request.files['file']
            try:
                import_method = ImportMethod.objects.get(acts_on=file.content_type)
                f = AttachedFile.from_upload(file)
                results = import_method.run(f)

                return render_template("{}/import.html".format(self.klass.__name__.lower()), import_results=results)
            except DoesNotExist:
                flash("This file type ('{}') is not supported.".format(file.content_type), "danger")
                return render_template("{}/import.html".format(self.klass.__name__.lower()))

    @route("/<id>/import", methods=['GET'])
    def import_from(self, id):
        investigation = get_object_or_404(Investigation, id=id)
        observables = Observable.from_string(investigation.import_text)

        return render_template("{}/import_from.html".format(self.klass.__name__.lower()), investigation=investigation, observables=bson_renderer(observables))
