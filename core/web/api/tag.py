from core.web.api.crud import CrudApi
from core.export import TagName
from core.web.api.api import render


class TagNameApi(CrudApi):
    template = "tag_names_api.html"
    objectmanager = TagName
