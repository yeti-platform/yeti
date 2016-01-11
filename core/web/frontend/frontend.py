from flask import Blueprint, render_template, request, redirect, url_for
from flask.ext.mongoengine.wtf import model_form

from core.observables import Observable
import core.entities as ent
from core.web.api.analysis import match_observables
from core.web.helpers import get_object_or_404
from core.web.api.api import bson_renderer
from core.helpers import refang

frontend = Blueprint("frontend", __name__, template_folder="templates", static_folder="staticfiles")

ENTITY_CLASS_MAP = {
    'ttp': ent.TTP,
    'actor': ent.Actor,
    'company': ent.Company,
    'malware': ent.Malware,
}


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
        node = get_object_or_404(ent.Entity, id=id)
    else:
        node = get_object_or_404(Observable, id=id)

    return render_template("graph_node.html", node=bson_renderer(node.to_mongo()))


# Entities

@frontend.route("/entities")
def entities():
    return render_template("entities.html")


@frontend.route("/entities/<id>")
def entity(id):
    e = ent.Entity.objects().get(id=id)
    return render_template("entity.html", entity=e)


@frontend.route("/entities/<id>/edit", methods=['GET', 'POST'])
def entity_edit(id):
    e = ent.Entity.objects().get(id=id)

    if request.method == "GET":
        form = model_form(e.__class__)(obj=e)
        return render_template("entity_new.html", form=form, entity_type=e.__class__.__name__, obj=e)

    elif request.method == "POST":

        form = model_form(e.__class__)(request.form, initial=e._data)
        if form.validate():
            form.populate_obj(e)
            e.save()
            return redirect(url_for('frontend.entity', id=id))
        else:
            return render_template("entity_new.html", form=form, entity_type=e.__class__.__name__, obj=e)


@frontend.route("/entities/new/<string:entity_type>", methods=['GET', 'POST'])
def entity_new(entity_type):
    klass = ENTITY_CLASS_MAP[entity_type]

    if request.method == "GET":
        form = model_form(klass)()
        return render_template("entity_new.html", form=form, entity_type=klass.__name__)

    elif request.method == "POST":
        form = model_form(klass)(request.form)
        if form.validate():
            obj = klass()
            form.populate_obj(obj)
            obj.save()
            return redirect(url_for('frontend.entity', id=obj.id))
        else:
            return render_template("entity_new.html", form=form, entity_type=klass.__name__, obj=None)


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
