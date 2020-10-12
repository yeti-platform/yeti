from flask import abort, request
from flask_classy import FlaskView, route
from flask_login import current_user
from mongoengine.errors import InvalidQueryError

from core.group import Group
from core.user import User
from core.web.api.api import render
from core.web.api.crud import CrudSearchApi
from core.web.helpers import get_object_or_404, requires_role


class UserAdminSearch(CrudSearchApi):
    template = "user_api.html"
    objectmanager = User

    @requires_role("admin")
    def post(self):
        """Launches a simple search against the database

        Overwrites the default behavior of CrudSearchApi to exclude
        sensitive user details.

        This endpoint is mostly used by paginators in Yeti.

        :<json object params: JSON object specifying the ``page``, ``range`` and ``regex`` variables.
        :<json integer params.page: Page or results to return (default: 1)
        :<json integer params.range: How many results to return (default: 50)
        :<json boolean params.regex: Set to true if the arrays in ``filter`` are to be treated as regular expressions (default: false)
        :<json object filter: JSON object specifying keys to be matched in the database. Each key must contain an array of OR-matched values.

        :reqheader Accept: must be set to ``application/json``
        :reqheader Content-Type: must be set to ``application/json``

        """
        query = request.get_json(silent=True) or {}

        try:
            data = self.search(query)
        except InvalidQueryError:
            abort(400)

        return render(data, self.template)


class UserAdmin(FlaskView):

    objectmanager = User

    @route("/<id>")
    @requires_role("admin")
    def get(self, id):
        user = get_object_or_404(User, id=id)
        user_info = user.info()
        user_info["groups"] = Group.objects(members__in=[user.id]).only("groupname")
        return render(user_info)

    @route("/remove/<id>", methods=["POST"])
    @requires_role("admin")
    def remove(self, id):
        user = get_object_or_404(User, id=id)
        user.delete()
        return render({"id": id})

    @route("/toggle/<id>", methods=["POST"])
    @requires_role("admin")
    def toggle(self, id):
        user = get_object_or_404(User, id=id)
        user.enabled = not user.enabled
        user.save()
        return render({"enabled": user.enabled, "id": id})

    @route("/toggle-admin/<id>", methods=["POST"])
    @requires_role("admin")
    def toggle_admin(self, id):
        user = get_object_or_404(User, id=id)
        user.permissions["admin"] = not user.permissions["admin"]
        return render(user.save())

    @route("/reset-api/<id>", methods=["POST"])
    @requires_role("admin")
    def reset_api(self, id):
        user = get_object_or_404(User, id=id)
        user.api_key = User.generate_api_key()
        return render(user.save())

    @route("/settings/<id>", methods=["POST"])
    def settings(self, id):
        user = get_object_or_404(User, id=id)
        settings = request.get_json()
        for setting in settings:
            user.settings[setting] = settings.get(setting)
        return render(user.save())

    @route("/permissions", methods=["POST"])
    @route("/permissions/<id>", methods=["POST"])
    @requires_role("admin")
    def permissions(self, id=None):
        if not id:
            user = current_user
        else:
            user = get_object_or_404(User, id=id)
        if not user:
            abort(400)
        permissions = request.get_json()
        sanitized = {}
        for key, values in permissions.items():
            if key == "admin":
                continue
            sanitized[key] = {k: bool(v) for k, v in values.items()}
        user.permissions.update(sanitized)
        return render(user.save())
