from flask import request, render_template, send_file, flash
from flask.ext.classy import route
from uuid import uuid4
from tempfile import gettempdir
from os import path

from core.web.frontend.generic import GenericView
from core.observables import *
from core.exports import ExportTemplate
from core.errors import ObservableValidationError
from core.analysis import match_observables
from core.web.helpers import get_object_or_404


class ObservablesView(GenericView):
    klass = Observable

    def pre_validate(self, obj, request):
        tags = obj.tags
        # redundant, but we need the object to be in the database for .tag to work
        obj.tags = []
        obj.save()
        obj.tag(tags, strict=True)

    @route('/advanced')
    def advanced(self):
        return render_template("{}/browse.html".format(self.klass.__name__.lower()), export_templates=ExportTemplate.objects.all())

    # override to guess observable type
    @route('/new', methods=["GET", "POST"])
    def new(self, klass=None):
        if not klass:
            klass = self.klass

        if request.method == "POST":
            if (request.form['type']
                and request.form['type'] in globals()
                and issubclass(globals()[request.form['type']], Observable)):
                guessed_type = globals()[request.form['type']]
            else:
                try:
                    guessed_type = Observable.guess_type(request.form['value'])
                except ObservableValidationError, e:
                    form = klass.get_form()(request.form)
                    form.errors['generic'] = [str(e)]
                    return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=klass.__name__, obj=None)

            return self.handle_form(klass=guessed_type)

        form = klass.get_form()()
        obj = None
        return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=klass.__name__, obj=obj)

    @route("/", methods=['GET', 'POST'])
    def index(self):
        if request.method == "POST":
            lines = []
            obs = {}
            if request.files.get('bulk-file'):  # request files
                pass
            else:
                lines = request.form['bulk-text'].split('\n')


            invalid_observables = 0
            if bool(request.form.get('add', False)):
                tags = request.form.get('tags', "").split(',')
                for l in lines:
                    try:
                        txt = l.strip()
                        if txt:
                            if (request.form['force-type']
                                and request.form['force-type'] in globals()
                                and issubclass(globals()[request.form['force-type']], Observable)):
                                print globals()[request.form['force-type']]
                                o = globals()[request.form['force-type']].get_or_create(value=txt)
                            else:
                                o = Observable.add_text(txt)
                            o.tag(tags)
                            obs[o.value] = o
                    except ObservableValidationError as e:
                        print "Error validating {}: {}".format(txt, e)
                        invalid_observables += 1
                        continue
            else:
                for l in lines:
                    obs[l.strip()] = l, None

            if len(obs) > 0:
                data = match_observables(obs.keys())
                return render_template("observable/search_results.html", data=data)
            else:
                if invalid_observables:
                    flash("Type guessing failed for {} observables. Try setting it manually.".format(invalid_observables), "danger")
                    return render_template("observable/search.html")

        return render_template("observable/search.html")

    @route("/export", methods=['POST'])
    def export(self):
        template = get_object_or_404(ExportTemplate, id=request.form['template'])
        ids = request.form.getlist('ids')

        filepath = path.join(gettempdir(), 'yeti_{}.txt'.format(uuid4()))
        template.render(Observable.objects(id__in=ids), filepath)

        return send_file(filepath)

    @route("/tag", methods=['POST'])
    def tag(self):
        ids = request.form.getlist('ids')
        tags = request.form['tags'].split(',')

        for observable in Observable.objects(id__in=ids):
            observable.tag(tags)

        return ('', 200)

    @route("/untag", methods=['POST'])
    def untag(self):
        ids = request.form.getlist('ids')
        tags = request.form['tags'].split(',')

        for observable in Observable.objects(id__in=ids):
            observable.untag(tags)

        return ('', 200)
