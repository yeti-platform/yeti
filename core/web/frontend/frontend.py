from flask import Blueprint, render_template, request, redirect, url_for
from flask.ext.classy import FlaskView, route

from core.investigation import Investigation
from core.observables import Observable
from core.entities import Entity
from core.web.frontend.generic import GenericView
from core.web.api.analysis import match_observables
from core.web.helpers import get_object_or_404
from core.web.api.api import bson_renderer
from core.helpers import refang

from core.entities import Entity, TTP, Actor, Company, Malware
from core.observables import Observable


frontend = Blueprint("frontend", __name__, template_folder="templates", static_folder="staticfiles")


# Landing page - redirect to observable

@frontend.route("/")
def index():
    return redirect(url_for('frontend.ObservablesView:index'))


# Entities - Generic View

class EntitiesView(GenericView):
    klass = Entity
    subclass_map = {
        'ttp': TTP,
        'actor': Actor,
        'company': Company,
        'malware': Malware,
    }

    # Query views


EntitiesView.register(frontend)


# Observables - Generic View

class ObservablesView(GenericView):
    klass = Observable

    @route("/enrich", methods=['GET', 'POST'])
    def enrich(self):
        return "ENRICH"
        if request.method == "POST":
            lines = request.form['bulk-text'].split('\n')
            for l in lines:
                obs = refang(l.split(',')[0])
                tags = refang(l.split(',')[1:])
                o = Observable.add_text(obs)
                o.tag(tags)
        return render_template('observable/query.html')

    @route("/query", methods=['GET', 'POST'])
    def query(self):
        if request.method == "POST":
            obs = [refang(o.strip()) for o in request.form['bulk-text'].split('\n')]
            data = match_observables(obs)
            return render_template("observable/query_results.html", data=data)

        return render_template("observable/query.html")


ObservablesView.register(frontend)


# Graph views

@frontend.route("/graph/<id>")
def graph(id):
    investigation = get_object_or_404(Investigation, id=id)
    return render_template("graph.html", investigation=bson_renderer(investigation.info()))


@frontend.route("/graph/<klass>/<id>")
def graph_node(klass, id):
    if klass == 'entity':
        node = get_object_or_404(Entity, id=id)
    else:
        node = get_object_or_404(Observable, id=id)

    investigation = Investigation().save()
    investigation.add([], [node])

    return render_template("graph.html", investigation=bson_renderer(investigation.info()))



# Admin views

@frontend.route("/dataflows")
def dataflows():
    return render_template("dataflows.html")


@frontend.route("/analytics")
def analytics():
    return render_template("analytics.html")


@frontend.route("/tags")
def tags():
    return render_template("tags.html")
