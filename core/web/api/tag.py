from core.web.api.crud import CrudApi
from core.observables import Tag, TagGroup


class TagApi(CrudApi):
    template = "tag_api.html"
    objectmanager = Tag


class TagGroupApi(CrudApi):
    template = "tag_groups_api.html"
    objectmanager = TagGroup
