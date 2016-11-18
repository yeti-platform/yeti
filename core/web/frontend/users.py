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

        return render_template("user/profile.html", available_settings=User.available_settings, user=user)

    @route('/reset-api', methods=["POST"])
    def reset_api(self):
        if request.args.get('id') and current_user.has_role('admin'):
            user = get_object_or_404(User, id=request.args.get('id'))
        else:
            user = current_user
        user.api_key = User.generate_api_key()
        user.save()
        flash("API key reset", "success")
        return redirect(request.referrer)



class UserAdminView(GenericView):
    klass = User

    @route('/reset-api/<id>', methods=["GET"])
    @requires_role('admin')
    def reset_api(self, id):
        print id, type(id)
        user = get_object_or_404(User, id=id)
        user.api_key = User.generate_api_key()
        user.save()
        flash("API key reset", "success")
        return redirect(request.referrer)
