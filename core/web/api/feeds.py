from core.web.api.crud import CrudApi
from core.feed import Feed

class FeedApi(CrudApi):

    template = 'feeds_api.html'
    objectmanager = Feed
