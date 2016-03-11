from flask.ext.classy import route

from core.web.api.crud import CrudApi
from core import feed
from core.web.api.api import render


class Feed(CrudApi):

    template = 'feeds_api.html'
    objectmanager = feed.Feed

    @route("/<id>/refresh", methods=["POST"])
    def refresh(self, id):
        feed.update_feed.delay(id)
        return render({"id": id})

    @route("/<id>/toggle", methods=["POST"])
    def toggle(self, id):
        f = self.objectmanager.objects.get(id=id)
        f.enabled = not f.enabled
        f.save()
        return render({"id": id, "status": f.enabled})
