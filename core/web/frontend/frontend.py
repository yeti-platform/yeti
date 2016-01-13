from flask import Blueprint, render_template, request, redirect, url_for

from core.web.frontend.generic import register_view
import core.entities as ent
from core.web.api.analysis import match_observables
from core.web.helpers import get_object_or_404
from core.web.api.api import bson_renderer
from core.helpers import refang

frontend = Blueprint("frontend", __name__, template_folder="templates", static_folder="staticfiles")


@frontend.route("/")
def index():
    return redirect(url_for('frontend.observable'))


# Entities

from core.entities import Entity, TTP, Actor, Company, Malware

class_map = {
    'ttp': TTP,
    'actor': Actor,
    'company': Company,
    'malware': Malware,
}




# observables

from core.observables import Observable

register_view(frontend, Observable, 'observable', '/observable/')
register_view(frontend, Entity, 'entity', '/entity/', class_map=class_map)

# @frontend.route("/observables")
# def observables():
#     return render_template("observables.html")
#
#
# @frontend.route("/observables/<id>")
# def observable(id):
#     o = Observable.objects.get(id=id)
#     return render_template("observable.html", observable=o)



@frontend.route("/graph/<id>")
def graph(id):
    o = Observable.objects.get(id=id)
    return render_template("graph.html", observable=o)


@frontend.route("/graph/<klass>/<id>")
def graph_node(klass, id):
    if klass == 'entity':
        node = get_object_or_404(ent.Entity, id=id)
    else:
        node = get_object_or_404(Observable, id=id)

    return render_template("graph_node.html", node=bson_renderer(node.to_mongo()))



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
