from flask import Blueprint, render_template, request, redirect, url_for

from core.observables import Observable
from core.entities import Entity
from core.web.api.analysis import match_observables
from core.web.helpers import get_object_or_404
from core.web.api.api import bson_renderer
from core.helpers import refang

frontend = Blueprint("frontend", __name__, template_folder="templates", static_folder="staticfiles")


@frontend.route("/")
def index():
    return redirect(url_for('frontend.observables'))


# observables

@frontend.route("/observables")
def observables():
    return render_template("observables.html")


@frontend.route("/observables/<id>")
def observable(id):
    o = Observable.objects.get(id=id)
    return render_template("observable.html", observable=o)


@frontend.route("/graph/<id>")
def graph(id):
    o = Observable.objects.get(id=id)
    return render_template("graph.html", observable=o)


@frontend.route("/graph/<klass>/<id>")
def graph_node(klass, id):
    if klass == 'entity':
        node = get_object_or_404(Entity, id=id)
    else:
        node = get_object_or_404(Observable, id=id)

    return render_template("graph_node.html", node=bson_renderer(node.to_mongo()))


# entities

@frontend.route("/entities")
def entities():
    return render_template("entities.html")


@frontend.route("/entities/<id>")
def entity(id):
    e = Entity.objects.get(id=id)
    return render_template("entity.html", entity=e)


@frontend.route("/query", methods=['GET', 'POST'])
def query():
    if request.method == "GET":
        return render_template("query.html")

    elif request.method == "POST":
        obs = [refang(o.strip()) for o in request.form['bulk-text'].split('\n')]
        data = match_observables(obs)
        return render_template("query_results.html", data=data)


# Admin section

@frontend.route("/dataflows")
def dataflows():
    return render_template("dataflows.html")


@frontend.route("/analytics")
def analytics():
    return render_template("analytics.html")


@frontend.route("/tags")
def tags():
    return render_template("tags.html")
