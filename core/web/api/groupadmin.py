from flask_classy import route

from core.web.api.crud import CrudSearchApi
from core.group import Group
from core.web.api.api import render
from core.web.helpers import requires_role, get_object_or_404

class GroupAdminSearch(CrudSearchApi):
    template = 'group_api.html'
    objectmanager = Group

    @route('/toggle/<gid>', methods=["POST"])
    @requires_role('admin')
    def toggle(self, id):
        group = get_object_or_404(Group, id=gid)
        group.enabled = not group.enabled
        group.save()
        return render({"enabled": group.enabled, "id": gid})

    @route('/remove/<gid>', methods=["POST"])
    @requires_role('admin')
    def remove(self, id):
        group = get_object_or_404(Group, id=gid)
        group.delete()
        return render({"id": gid})
