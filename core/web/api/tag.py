from core.web.api.crud import CrudApi
from core.observables import TagName, TagGroup
from core.web.api.api import render


class TagNameApi(CrudApi):
    template = "tag_names_api.html"
    objectmanager = TagName


class TagGroupApi(CrudApi):
    template = "tag_groups_api.html"
    objectmanager = TagGroup
