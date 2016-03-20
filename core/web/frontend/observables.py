from flask import request, render_template
from flask.ext.classy import route

from core.web.frontend.generic import GenericView
from core.observables import Observable
from core.errors import ObservableValidationError
from core.analysis import match_observables


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
        return render_template("{}/browse.html".format(self.klass.__name__.lower()))

    # override to guess observable type
    @route('/new', methods=["GET", "POST"])
    def new(self, klass=None):
        if not klass:
            klass = self.klass
        if request.method == "POST":
            guessed_type = Observable.guess_type(request.form['value'])
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

            if bool(request.form.get('add', False)):
                tags = request.form.get('tags', "").split(',')
                for l in lines:
                    try:
                        txt = l.strip()
                        if txt:
                            o = Observable.add_text(txt)
                            o.tag(tags)
                            obs[o.value] = o
                    except ObservableValidationError:
                        continue
            else:
                for l in lines:
                    obs[l.strip()] = l, None

            data = match_observables(obs.keys())
            return render_template("observable/search_results.html", data=data)

        return render_template("observable/search.html")
