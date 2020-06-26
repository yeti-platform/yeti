from flask import request
from flask_classy import FlaskView, route
from flask_login import current_user

from core.group import Group
from core.user import User
from core.web.api.api import render


class Users(FlaskView):

    def get(self):
        user_info = current_user.info()
        user_info['groups'] = Group.objects(members__in=[current_user.id]).only(
            'groupname')
        return render(user_info)

    @route('/reset-api', methods=["POST"])
    def reset_api(self):
        current_user.api_key = User.generate_api_key()
        return render(current_user.save())

    @route('/settings', methods=["POST"])
    def settings(self):
        settings = request.get_json()
        for setting in settings:
            current_user.settings[setting] = settings.get(setting)
        return render(current_user.save())
