from core.web.api.crud import CrudApi
from core.feed import Feed, update_feed
from core.web.api.api import render


class FeedApi(CrudApi):

    template = 'feeds_api.html'
    objectmanager = Feed

    def post(self, name, action):
        if action == "refresh":
            update_feed.delay(name)
            return render({"name": name})
        elif action == "toggle":
            f = Feed.objects.get(name=name)
            f.enabled = not f.enabled
            f.save()
            return render({"name": name, "status": f.enabled})
