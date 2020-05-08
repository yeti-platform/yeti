from flask_classy import route

from core.web.api.crud import CrudSearchApi, CrudApi
from core.user import User
from core.web.api.api import render
from core.web.helpers import requires_role, get_object_or_404


class UserAdminSearch(CrudSearchApi):
    template = 'user_api.html'
    objectmanager = User

    @route('/toggle/<id>', methods=["POST"])
    @requires_role('admin')
    def toggle(self, id):
        user = get_object_or_404(User, id=id)
        user.enabled = not user.enabled
        user.save()
        return render({"enabled": user.enabled, "id": id})

    @route('/remove/<id>', methods=["POST"])
    @requires_role('admin')
    def remove(self, id):
        user = get_object_or_404(User, id=id)
        user.delete()
        return render({"id": id})

class UserAdmin(CrudApi):

    objectmanager = User

    @route('/reset-api/<id>', methods=["GET", "POST"])
    @requires_role('admin')
    def reset_api(self, id):
        user = get_object_or_404(User, id=id)
        user.api_key = User.generate_api_key()
        return render(user.save())
