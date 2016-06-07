from __future__ import unicode_literals

from core.web.api.crud import CrudSearchApi, CrudApi
from core import database


class LinkSearch(CrudSearchApi):
    objectmanager = database.Link


class Link(CrudApi):
    objectmanager = database.Link
