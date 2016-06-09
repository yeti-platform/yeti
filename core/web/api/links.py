from __future__ import unicode_literals

from flask_classy import route
from bson.json_util import loads
from flask import request

from core.web.api.crud import CrudSearchApi, CrudApi
from core import database
from core.web.api.api import render
from core.helpers import iterify


class LinkSearch(CrudSearchApi):
    objectmanager = database.Link


class Link(CrudApi):
    objectmanager = database.Link

    @route("/multiupdate", methods=['POST'])
    def multiupdate(self):
        data = loads(request.data)
        ids = data['ids']
        new_description = data['new']['description']
        updated = []
        for link in self.objectmanager.objects(id__in=ids):
            # link.select_related() #does not work
            # must call src and dst to dereference dbrefs and not raise an exception
            link.src
            link.dst
            link.description = new_description
            link.save()
            updated.append(link.id)

        return render({"updated": updated})
