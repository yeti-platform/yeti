from flask import Blueprint, render_template, request, redirect, url_for
from flask.ext.classy import route
from flask import g

from core.investigation import Investigation
from core.observables import Observable, Hostname, Ip, Url, Hash, Text, File, Email
from core.entities import Entity
from core.indicators import Indicator, Regex
from core.analysis import match_observables
from core.web.frontend.generic import GenericView
from core.web.helpers import get_object_or_404
from core.web.api.api import bson_renderer
from core.entities import TTP, Actor, Company, Malware
from core.errors import ObservableValidationError


frontend = Blueprint("frontend", __name__, template_folder="templates", static_folder="staticfiles")


@frontend.before_request
def before_request():
    g.entities = [TTP, Actor, Company, Malware]
    g.observables = [Hostname, Ip, Url, Hash, Text, File, Email]
    g.indicators = [Regex]

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

EntitiesView.register(frontend)


# Indicators - Generic View

class IndicatorsView(GenericView):
    klass = Indicator
    subclass_map = {
        'regex': Regex,
    }

IndicatorsView.register(frontend)

# Observables - Generic View

class ObservablesView(GenericView):
    klass = Observable

    def pre_validate(self, obj):
        tags = obj.tags
        # redundant, but we need the object to be in the database for .tag to work
        obj.tags = []
        obj.save()
        obj.tag(tags, strict=True)

    # override to guess observable type
    @route('/new/', methods=["GET", "POST"])
    def new(self, klass=None):
        if not klass:
            klass = self.klass
        if request.method == "POST":
            guessed_type = Observable.guess_type(request.form['value'])
            return self.handle_form(klass=guessed_type)
        form = klass.get_form()()
        obj = None
        return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=klass.__name__, obj=obj)

    @route("/query", methods=['GET', 'POST'])
    def query(self):
        if request.method == "POST":
            lines = []
            obs = {}
            if request.files.get('bulk-file'): # request files
                pass
            else:
                lines = request.form['bulk-text'].split('\n')

            if bool(request.form.get('add', False)):
                tags = request.form.get('tags', "").split(',')
                for l in lines:
                    try:
                        o = Observable.add_text(l.strip())
                        o.tag(tags)
                    except ObservableValidationError:
                        continue
                    obs[o.value] = o
            else:
                for l in lines:
                    obs[l.strip()] = l, None

            data = match_observables(obs.keys())
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
