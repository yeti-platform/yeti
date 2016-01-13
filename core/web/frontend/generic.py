from flask.views import MethodView
from flask.ext.mongoengine.wtf import model_form
from flask import render_template, request, redirect, url_for


def register_view(frontend, klass, endpoint, url, class_map=None):

    GenericDisplay.klass = klass
    GenericEdit.klass = klass
    GenericEdit.class_map = class_map

    frontend.add_url_rule('{}'.format(url), view_func=GenericDisplay.as_view('{}'.format(endpoint)))
    frontend.add_url_rule('{}<id>'.format(url), view_func=GenericDisplay.as_view('{}_display'.format(endpoint)))

    frontend.add_url_rule('{}new/<string:entity_type>'.format(url), view_func=GenericEdit.as_view('{}_new'.format(endpoint)))
    frontend.add_url_rule('{}<id>/edit'.format(url), view_func=GenericEdit.as_view('{}_edit'.format(endpoint)))


class GenericDisplay(MethodView):

    klass = None

    def get(self, id=None):
        if id:  # list
            e = self.klass.objects().get(id=id)
            return render_template("{}/single.html".format(self.klass.__name__.lower()), entity=e)
        else:  # display
            print self.klass.__name__
            return render_template("{}/list.html".format(self.klass.__name__.lower()))


class GenericEdit(MethodView):

    klass = None
    class_map = {}

    def get(self, id=None, entity_type=None):
        if not id:  # new, empty form
            if self.class_map:
                klass = self.class_map[entity_type]
            form = model_form(klass)()
            obj = None
        else:  # prepopulated form
            obj = self.klass.objects().get(id=id)
            form = model_form(obj.__class__)(obj=obj)
            klass = obj.__class__

        return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=klass.__name__, obj=obj)

    def post(self, id=None, entity_type=None):
        if not id:  # create
            if self.class_map:
                klass = self.class_map[entity_type]
            obj = klass()
            form = model_form(klass)(request.form)
        else:  # update
            obj = self.klass.objects().get(id=id)
            klass = obj.__class__
            form = model_form(klass)(request.form, initial=obj._data)

        if form.validate():
            form.populate_obj(obj)
            obj.save()
            return redirect(url_for('frontend.{}_display'.format(self.klass.__name__.lower()), id=obj.id))
        else:
            return render_template("{}/edit.html".format(self.klass.__name__.lower()), form=form, obj_type=klass.__name__, obj=obj)
