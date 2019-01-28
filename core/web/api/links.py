from __future__ import unicode_literals
import time

from flask_classy import route
from bson.json_util import loads
from flask import request

from core.web.api.crud import CrudSearchApi, CrudApi
from core import database, observables, entities, indicators
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

    @route("/", methods=['POST'])
    @requires_permissions('write')
    def new(self):
        """Create a new link

        Create a new link from the JSON object passed in the ``POST`` data.

        :<json object params: JSON object containing object ids to link
        """
        params = request.json
        type_src = params.pop('type_src', None)
        type_dst = params.pop('type_dst', None)
        db_objects_src = None
        db_objects_dst = None

        if type_src == 'observable':
            db_objects_src = observables.Observable
        elif type_src == 'entity':
            db_objects_src = entities.Entity
        elif type_src == 'indicator':
            db_objects_src = indicators.Indicator

        if type_dst == 'observable':
            db_objects_dst = observables.Observable
        elif type_dst == 'entity':
            db_objects_dst = entities.Entity
        elif type_dst == 'indicator':
            db_objects_dst = indicators.Indicator

        if (db_objects_src is not None) and (db_objects_dst is not None):
            src = db_objects_src.objects.get(id=params.pop("link_src"))
            dst = db_objects_dst.objects.get(id=params.pop("link_dst"))

            if (params.pop("first_seen", None) is not None) and \
               (params.pop("last_seen", None) is not None):
                link = src.link_to(dst,
                                   params.pop("description"),
                                   params.pop("source"),
                                   params.pop("first_seen", None),
                                   params.pop("last_seen", None))
            else:
                link = src.active_link_to(dst, params.pop("description"),
                                          params.pop("source"))

        else:
            link = None

        return render({"link": link})
