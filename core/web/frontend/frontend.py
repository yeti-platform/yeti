from __future__ import unicode_literals

from flask import Blueprint, render_template, redirect, url_for
from flask import g

from core.investigation import Investigation
from core.web.helpers import get_object_or_404
from core.web.api.api import bson_renderer

from core.web.frontend.entities import EntitiesView
from core.web.frontend.observables import ObservablesView
from core.web.frontend.indicators import IndicatorsView
from core.web.frontend.investigations import InvestigationsView

from core.observables import *
from core.entities import *
from core.indicators import *
from core.exports import ExportTemplate
from core.web.frontend.users import UsersView

frontend = Blueprint("frontend", __name__, template_folder="templates", static_folder="staticfiles")


@frontend.before_request
def before_request():
    g.entities = []
    g.observables = []
    g.indicators = []
    for key, value in globals().items():
        try:
            if issubclass(value, Entity) and value is not Entity:
                g.entities.append(value)
            if issubclass(value, Observable) and value is not Observable:
                g.observables.append(value)
            if issubclass(value, Indicator) and value is not Indicator:
                g.indicators.append(value)
        except TypeError:
            pass

# Landing page - redirect to observable

@frontend.route("/")
def index():
    return redirect(url_for('frontend.ObservablesView:index'))


UsersView.register(frontend)

EntitiesView.register(frontend)
IndicatorsView.register(frontend)
ObservablesView.register(frontend)
InvestigationsView.register(frontend)

# Graph views

@frontend.route("/graph/<id>")
def graph(id):
    investigation = get_object_or_404(Investigation, id=id)
    return render_template("graph.html", investigation=bson_renderer(investigation.info()))


@frontend.route("/graph/<klass>/<id>")
def graph_node(klass, id):
    if klass == 'entity':
        node = get_object_or_404(Entity, id=id)
    elif klass == 'indicator':
        node = get_object_or_404(Indicator, id=id)
    else:
        node = get_object_or_404(Observable, id=id)

    investigation = Investigation().save()
    investigation.add([], [node])

    return render_template("graph.html", investigation=bson_renderer(investigation.info()))


# Admin views

@frontend.route("/dataflows")
def dataflows():
    return render_template("dataflows.html", export_templates=ExportTemplate.objects.all())


@frontend.route("/analytics")
def analytics():
    return render_template("analytics.html")


@frontend.route("/tags")
def tags():
    return render_template("tags.html")
