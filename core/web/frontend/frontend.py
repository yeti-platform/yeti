from flask import Blueprint, render_template, request, redirect, url_for
from flask.views import MethodView
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

class EntitiesView(MethodView):
    def get(self, id=None):
        if id:
            e = ent.Entity.objects().get(id=id)
            return render_template("entity.html", entity=e)
        else:
            return render_template("entities.html")

frontend.add_url_rule('/entities', view_func=EntitiesView.as_view('entities'))
frontend.add_url_rule('/entities/<id>', view_func=EntitiesView.as_view('entity'))


class EntitiesEdit(MethodView):

    class_map = {
        'ttp': ent.TTP,
        'actor': ent.Actor,
        'company': ent.Company,
        'malware': ent.Malware,
    }

    def get(self, id=None, entity_type=None):
        if not id:  # new
            klass = self.class_map[entity_type]
            form = model_form(klass)()
            e = None
        else:  # edit form
            e = ent.Entity.objects().get(id=id)
            form = model_form(e.__class__)(obj=e)
            klass = e.__class__

        return render_template("entity_new.html", form=form, entity_type=klass.__name__, obj=e)

    def post(self, id=None, entity_type=None):
        if not id:
            klass = self.class_map[entity_type]
            obj = klass()
            form = model_form(klass)(request.form)
        else:
            obj = ent.Entity.objects().get(id=id)
            klass = obj.__class__
            form = model_form(klass)(request.form, initial=obj._data)

        if form.validate():
            form.populate_obj(obj)
            obj.save()
            return redirect(url_for('frontend.entity', id=obj.id))
        else:
            return render_template("entity_new.html", form=form, entity_type=klass.__name__, obj=None)

frontend.add_url_rule('/entities/new/<string:entity_type>', view_func=EntitiesEdit.as_view('entity_new'))
frontend.add_url_rule('/entities/<id>/edit', view_func=EntitiesEdit.as_view('entity_edit'))



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
