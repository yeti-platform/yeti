from flask_classy import route

from core.web.api.crud import CrudSearchApi, CrudApi
from core.user import User
from core.web.api.api import render
from core.web.helpers import requires_role, get_object_or_404


class UserAdminSearch(CrudSearchApi):
    template = 'user_api.html'
    objectmanager = User

    @route('/remove/<id>', methods=["POST"])
    @requires_role('admin')
    def remove(self, id):
        user = get_object_or_404(User, id=id)
        user.delete()
        return render({"id": id})

class UserAdmin(CrudApi):

    objectmanager = User

    @route('/toggle/<id>', methods=["POST"])
    @requires_role('admin')
    def toggle(self, id):
        user = get_object_or_404(User, id=id)
        user.enabled = not user.enabled
        user.save()
        return render({"enabled": user.enabled, "id": id})

    @route('/toggle-admin/<id>', methods=["POST"])
    @requires_role('admin')
    def toggle_admin(self, id):
        user = get_object_or_404(User, id=id)
        user.permissions['admin'] = not user.permissions['admin']
        return render(user.save())

    @route('/reset-api/<id>', methods=["POST"])
    @requires_role('admin')
    def reset_api(self, id):
        user = get_object_or_404(User, id=id)
        user.api_key = User.generate_api_key()
        return render(user.save())

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
