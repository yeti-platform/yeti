from __future__ import unicode_literals

from flask import render_template, request, redirect, flash
from flask_login import current_user
from flask_classy import FlaskView, route

from core.user import User


class UsersView(FlaskView):
    @route('/settings', methods=["GET", "POST"])
    def settings(self):
        if request.method == "POST":
            for setting in request.form:
                if request.form[setting]:
                    current_user.settings[setting] = request.form[setting]

            current_user.save()

            for setting in request.form:
                if not request.form[setting]:
                    current_user.settings.pop(setting, None)

            current_user.save()

        return render_template("user/settings.html", available_settings=User.available_settings)

    @route('/reset-api', methods=["POST"])
    def reset_api(self):
        current_user.api_key = User.generate_api_key()
        current_user.save()
        flash("API key reset", "success")
        return redirect(request.referrer)
