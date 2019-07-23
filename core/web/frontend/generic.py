from __future__ import unicode_literals

from flask_classy import FlaskView, route
from flask_login import current_user
from flask import render_template, request, redirect, url_for, abort
from mongoengine import NotUniqueError

from core.entities import Malware, Company, TTP, Actor
from core.errors import GenericValidationError
from core.indicators import Regex
from core.database import AttachedFile
from core.web.helpers import get_object_or_404
from core.web.helpers import requires_permissions, group_user_permission, get_user_groups

binding_object_classes = {
    "malware": Malware,
    "company": Company,
    "ttp": TTP,
    "actor": Actor,
    "regex": Regex,
}


class GenericView(FlaskView):

    subclass_map = {}

    @requires_permissions("read")
    def index(self):
        return render_template(
            "{}/list.html".format(self.klass.__name__.lower()))

    @requires_permissions("read")
    def get(self, id):
        obj = self.klass.objects.get(id=id)
        if hasattr(obj, "sharing"):
            if group_user_permission(obj):
                return render_template(
                    "{}/single.html".format(self.klass.__name__.lower()), obj=obj)
            abort(403)
        else:
            return render_template(
                "{}/single.html".format(self.klass.__name__.lower()), obj=obj)

        return(request.referrer)

    @requires_permissions("write")
    @route('/new/<string:subclass>', methods=["GET", "POST"])
    def new_subclass(self, subclass):
        klass = self.subclass_map.get(subclass, self.klass)
        return self.new(klass)

    @requires_permissions("write")
    @route('/new', methods=["GET", "POST"])
    def new(self, klass=None):
        if not klass:
            klass = self.klass
        if request.method == "POST":
            return self.handle_form(klass=klass)

        if 'bind' in request.args and request.args.get(
                "type") in binding_object_classes:
            objtype = binding_object_classes[request.args.get("type")]
            binding_obj = objtype.objects.get(id=request.args.get('bind'))
            form = klass.get_form()(links=[binding_obj.name])
        else:
            form = klass.get_form()()

        obj = None
        return render_template(
            "{}/edit.html".format(self.klass.__name__.lower()),
            form=form,
            obj_type=klass.__name__,
            obj=obj)

    @requires_permissions("write")
    @route('/edit/<string:id>', methods=["GET", "POST"])
    def edit(self, id):
        obj = self.klass.objects.get(id=id)
        #ToDo Group admins support
        if current_user.username != getattr(obj, 'created_by') and not current_user.has_role('admin'):
            abort(403)

        if request.method == "POST":
            return self.handle_form(id=id)

        form_class = obj.__class__.get_form()
        form = form_class(obj=obj)
        return render_template(
            "{}/edit.html".format(self.klass.__name__.lower()),
            form=form,
            obj_type=self.klass.__name__,
            obj=obj,
            groups=get_user_groups())

    @requires_permissions("write")
    @route('/delete/<string:id>', methods=["GET"])
    def delete(self, id):
        obj = self.klass.objects.get(id=id)
        #ToDo Group admins support
        if current_user.username != getattr(obj, "created_by") and not current_user.has_role('admin'):
            abort(403)
        obj.delete()
        return redirect(
            url_for('frontend.{}:index'.format(self.__class__.__name__)))

    def pre_validate(self, obj, request):
        pass

    def post_save(self, obj, request):
        pass

    def create_obj(self, obj, skip_validation):
        obj = obj.save(validate=not skip_validation)
        self.post_save(obj, request)
        return obj

    def handle_form(self, id=None, klass=None, skip_validation=False):
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
                obj = self.create_obj(obj, skip_validation)
                if form.formdata.get("sharing") and hasattr(klass, "sharing_permissions"):
                    obj.sharing_permissions(form.formdata["sharing"], invest_id=obj.id)
            except GenericValidationError as e:
                # failure - redirect to edit page
                form.errors['General Error'] = [e]
                return render_template(
                    "{}/edit.html".format(self.klass.__name__.lower()),
                    form=form,
                    obj_type=klass.__name__,
                    obj=None,
                    groups=get_user_groups())
            except NotUniqueError as e:
                form.errors['Duplicate'] = [
                    'Entity "{}" is already in the database'.format(obj)
                ]
                return render_template(
                    "{}/edit.html".format(self.klass.__name__.lower()),
                    form=form,
                    obj_type=klass.__name__,
                    obj=None,
                    groups=get_user_groups())

            # success - redirect to view page
            return redirect(
                url_for(
                    'frontend.{}:get'.format(self.__class__.__name__),
                    id=obj.id))
        else:
            return render_template(
                "{}/edit.html".format(self.klass.__name__.lower()),
                form=form,
                obj_type=klass.__name__,
                obj=obj)

    @requires_permissions("write")
    @route('/<string:id>/attach-file', methods=["POST"])
    def attach_file(self, id):
        if 'file' not in request.files:
            abort(400)

        e = get_object_or_404(self.klass, id=id)
        f = AttachedFile.from_upload(request.files['file'])
        if f:
            f.attach(e)
        return redirect(
            url_for('frontend.{}:get'.format(self.__class__.__name__), id=e.id))

    @requires_permissions("write")
    @route('/<string:id>/detach-file/<string:fileid>', methods=["GET"])
    def detach_file(self, id, fileid):
        f = get_object_or_404(AttachedFile, id=fileid)
        e = get_object_or_404(self.klass, id=id)
        f.detach(e)
        return redirect(
            url_for('frontend.{}:get'.format(self.__class__.__name__), id=id))
