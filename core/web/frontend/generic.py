from flask.ext.classy import FlaskView, route
from flask.ext.mongoengine.wtf import model_form
from flask import render_template, request, redirect, url_for


class GenericView(FlaskView):

    def index(self):
        return render_template("{}/list.html".format(self.klass.__name__.lower()))

    def get(self, id):
        obj = self.klass.objects().get(id=id)
        return render_template("{}/single.html".format(self.klass.__name__.lower()), obj=obj)

    @route('/new/', methods=["GET", "POST"])
    @route('/new/<string:subclass>', methods=["GET", "POST"])
    def new(self, subclass=None):
        klass = self.subclass_map.get(subclass, self.klass)
        if request.method == "POST":
            return self.handle_form(klass=klass)
        form = model_form(klass)()
        obj = None
        return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=klass.__name__, obj=obj)

    @route('/edit/<string:id>', methods=["GET", "POST"])
    def edit(self, id):
        if request.method == "POST":
            return self.handle_form(id=id)
        obj = self.klass.objects().get(id=id)
        form = model_form(obj.__class__)(obj=obj)
        return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=self.klass.__name__, obj=obj)

    def handle_form(self, id=None, klass=None):
        if klass:  # create
            obj = klass()
            form = model_form(klass)(request.form)
        else:  # update
            obj = self.klass.objects().get(id=id)
            klass = obj.__class__
            form = model_form(klass)(request.form, initial=obj._data)

        if form.validate():
            form.populate_obj(obj)
            obj.save()
            return redirect(url_for('frontend.{}:get'.format(self.__class__.__name__), id=obj.id))
        else:
            return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=klass.__name__, obj=obj)
