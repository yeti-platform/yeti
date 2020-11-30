from __future__ import unicode_literals

from flask_classy import route

from core.web.api.crud import CrudApi
from core import feed
from core.web.api.api import render
from core.web.helpers import requires_permissions


class Feed(CrudApi):

    template = "feeds_api.html"
    objectmanager = feed.Feed

    @route("/<id>/refresh", methods=["POST"])
    @requires_permissions("refresh")
    def refresh(self, id):
        """Runs a Feed

        :query ObjectID id: Feed ID
        :>json ObjectId id: Feed ID

        """
        feed.update_feed.delay(id)
        return render({"id": id})

    @route("/<id>/toggle", methods=["POST"])
    @requires_permissions("toggle")
    def toggle(self, id):
        """Toggles a Feed

        Feeds can be individually disabled using this endpoint.

        :query ObjectID id: Analytics ID
        :>json ObjectID id: The Analytics's ObjectID
        :>json boolean status: The result of the toggle operation (``true`` means the export has been enabled, ``false`` means it has been disabled)
        """
        f = self.objectmanager.objects.get(id=id)
        f.enabled = not f.enabled
        f.save()
        return render({"id": id, "status": f.enabled})
