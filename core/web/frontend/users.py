from __future__ import unicode_literals

from flask import render_template, request, redirect, flash
from flask_login import current_user
from flask_classy import route

from core.web.frontend.generic import GenericView
from core.user import User
from core.web.helpers import requires_role, get_object_or_404


class UsersView(GenericView):

    klass = User

    @route('/profile', methods=["GET", "POST"])
    def profile(self):
        if request.args.get('id') and current_user.has_role('admin'):
            user = get_object_or_404(User, id=request.args.get('id'))
        else:
            user = current_user

        if request.method == "POST":
            for setting in request.form:
                if request.form[setting]:
                    user.settings[setting] = request.form[setting]

            user.save()

            for setting in request.form:
                if not request.form[setting]:
                    user.settings.pop(setting, None)

            user.save()

        if current_user.has_role('admin') and user.id != current_user.id:
            return render_template(
                "user/profile_admin.html",
                available_settings=User.get_available_settings(),
                user=user)
        else:
            return render_template(
                "user/profile.html",
                available_settings=User.get_available_settings(),
                user=user)

    @route('/reset-api', methods=["POST"])
    def reset_api(self):
        current_user.api_key = User.generate_api_key()
        current_user.save()
        flash("API key reset", "success")
        return redirect(request.referrer)


class UserAdminView(GenericView):
    klass = User

    @route('/reset-api/<id>', methods=["GET", "POST"])
    @requires_role('admin')
    def reset_api(self, id):
        user = get_object_or_404(User, id=id)
        user.api_key = User.generate_api_key()
        user.save()
        flash("API key reset", "success")
        return redirect(request.referrer)

    @route("/permissions/<id>", methods=['GET', 'POST'])
    @requires_role('admin')
    def permissions(self, id):
        user = get_object_or_404(User, id=id)
        permdict = {}
        if request.method == "POST":
            for object_name, permissions in user.permissions.items():
                if not isinstance(permissions, dict):
                    permdict[object_name] = bool(
                        request.form.get("{}".format(object_name), False))
                else:
                    if object_name not in permdict:
                        permdict[object_name] = {}
                    for p in permissions:
                        permdict[object_name][p] = bool(
                            request.form.get(
                                "{}_{}".format(object_name, p), False))
            user.permissions = permdict
            user.save()
            flash("Permissions changed successfully", "success")
        return redirect(request.referrer)
        return render_template("user/permissions.html", user=user)
