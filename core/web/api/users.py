from flask import request, abort
from flask_classy import route

from flask_classy import FlaskView, route
from core import observables
from core.web.api.api import render
from core.errors import TagValidationError
from core.web.helpers import requires_permissions
from core.web.helpers import get_object_or_404
from flask_login import current_user
from core.user import User
from core.group import Group
from core.web.api.api import render

class Users(FlaskView):

    def get(self):
        user = get_object_or_404(User, id=current_user.id)
        return render(user.info())

    @route('/reset-api', methods=["POST"])
    def reset_api(self):
        current_user.api_key = User.generate_api_key()
        return render(current_user.save())
