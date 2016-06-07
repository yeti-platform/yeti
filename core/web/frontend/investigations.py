from __future__ import unicode_literals

from flask_classy import route
from flask import render_template

from core.web.frontend.generic import GenericView
from core.investigation import Investigation
from core.web.helpers import get_object_or_404

from core.entities import Entity
from core.indicators import Indicator
from core.observables import Observable

from core.web.api.api import bson_renderer


class InvestigationsView(GenericView):

    klass = Investigation

    @route("/graph/<id>")
    def graph(self, id):
        investigation = get_object_or_404(Investigation, id=id)
        return render_template("{}/graph.html".format(self.klass.__name__.lower()), investigation=bson_renderer(investigation.info()))

    @route("/graph/<klass>/<id>")
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
