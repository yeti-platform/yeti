from flask_classy import route

from core.web.api.crud import CrudSearchApi
from core.group import Group
from core.web.api.api import render
from core.web.helpers import requires_role, get_object_or_404

class GroupAdminSearch(CrudSearchApi):
    template = 'group_api.html'
    objectmanager = Group

    @route('/toggle/<id>', methods=["POST"])
    @requires_role('admin')
    def toggle(self, id):
        group = get_object_or_404(Group, id=id)
        group.enabled = not group.enabled
        group.save()
        return render({"enabled": group.enabled, "id": id})

    @route('/remove/<id>', methods=["POST"])
    @requires_role('admin')
    def remove(self, id):
        group = get_object_or_404(Group, id=id)
        group.delete()
        return render({"id": id})
