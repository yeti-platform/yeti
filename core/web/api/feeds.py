from flask_restful import abort as restful_abort

from core.web.api.crud import CrudApi
from core import feed
from core.web.api.api import render


class Feed(CrudApi):

    template = 'feeds_api.html'
    objectmanager = feed.Feed

    def post(self, id, action):
        if action not in ["refresh", "toggle"]:
            restful_abort(400, error="action must be either refresh or toggle")
        if action == "refresh":
            feed.update_feed.delay(id)
            return render({"id": id})
        elif action == "toggle":
            f = self.objectmanager.objects.get(id=id)
            f.enabled = not f.enabled
            f.save()
            return render({"id": id, "status": f.enabled})
