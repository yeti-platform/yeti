from __future__ import unicode_literals
import time

from flask_classy import route
from bson.json_util import loads
from flask import request

from core.web.api.crud import CrudSearchApi, CrudApi
from core import database
from core.web.api.api import render
from core.helpers import iterify
from core.investigation import Investigation
from core.web.helpers import requires_permissions


class LinkSearch(CrudSearchApi):
    objectmanager = database.Link


class Link(CrudApi):
    objectmanager = database.Link

    @requires_permissions('write')
    def delete(self, id):
        """Deletes the corresponding entry from the database

        :query ObjectID id: Element ID
        :>json string deleted: The deleted element's ObjectID
        """
        obj = self.objectmanager.objects.get(id=id)
        for i, inv in enumerate(Investigation.objects(links__id=id)):
            inv.modify({
                "links__id": id
            },
                       set__links__S__id="local-{}-{}".format(time.time(), i))
        obj.delete()
        return render({"deleted": id})

    @route("/multidelete", methods=['POST'])
    @requires_permissions('write')
    def multidelete(self):
        data = loads(request.data)
        ids = iterify(data['ids'])
        for i, inv in enumerate(Investigation.objects(links__id__in=ids)):
            inv.modify({
                "links__id": id
            },
                       set__links__S__id="local-{}-{}".format(time.time(), i))
        self.objectmanager.objects(id__in=ids).delete()
        return render({"deleted": ids})

    @route("/multiupdate", methods=['POST'])
    @requires_permissions('write')
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
