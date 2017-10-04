from __future__ import unicode_literals

from flask import Blueprint, render_template, redirect, url_for
from flask import g

from core.web.frontend.entities import EntityView
from core.web.frontend.observables import ObservableView
from core.web.frontend.indicators import IndicatorView
from core.web.frontend.investigations import InvestigationView
from core.web.frontend.system import SystemView
from core.web.frontend.actions import ActionsView

from core.observables import *
from core.entities import *
from core.indicators import *
from core.exports import ExportTemplate
from core.web.frontend.users import UsersView, UserAdminView

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
    return redirect(url_for('frontend.ObservableView:index'))


UsersView.register(frontend)
UserAdminView.register(frontend)
EntityView.register(frontend)
IndicatorView.register(frontend)
ObservableView.register(frontend)
InvestigationView.register(frontend)
SystemView.register(frontend)
ActionsView.register(frontend)

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

# @frontend.route("/system")
# def system():
#     return render_template("system.html")
