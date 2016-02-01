from flask.ext.classy import FlaskView, route
from flask import render_template, request, redirect, url_for
from mongoengine import NotUniqueError

from core.errors import ObservableValidationError


class GenericView(FlaskView):

    subclass_map = {}

    def index(self):
        return render_template("{}/list.html".format(self.klass.__name__.lower()))

    def get(self, id):
        obj = self.klass.objects.get(id=id)
        return render_template("{}/single.html".format(self.klass.__name__.lower()), obj=obj)

    @route('/new/<string:subclass>', methods=["GET", "POST"])
    def new_subclass(self, subclass):
        klass = self.subclass_map.get(subclass, self.klass)
        return self.new(klass)

    @route('/new/', methods=["GET", "POST"])
    def new(self, klass=None):
        if not klass:
            klass = self.klass
        if request.method == "POST":
            return self.handle_form(klass=klass)
        form = klass.get_form()()
        obj = None
        return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=klass.__name__, obj=obj)

    @route('/edit/<string:id>', methods=["GET", "POST"])
    def edit(self, id):
        if request.method == "POST":
            return self.handle_form(id=id)
        obj = self.klass.objects.get(id=id)
        form_class = obj.__class__.get_form()
        form = form_class(obj=obj)
        return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=self.klass.__name__, obj=obj)

    def handle_form(self, id=None, klass=None):
        if klass:  # create
            obj = klass()
            form = klass.get_form()(request.form)
        else:  # update
            obj = self.klass.objects.get(id=id)
            klass = obj.__class__
            form = klass.get_form()(request.form, initial=obj._data)

        if form.validate():
            form.populate_obj(obj)
            try:
                obj.save()
            except (ObservableValidationError, NotUniqueError) as e:
                # failure - redirect to edit page
                form.errors['generic'] = [str(e)]
                return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=klass.__name__, obj=None)

            # success - redirect to view page
            return redirect(url_for('frontend.{}:get'.format(self.__class__.__name__), id=obj.id))
        else:
            return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=klass.__name__, obj=obj)
