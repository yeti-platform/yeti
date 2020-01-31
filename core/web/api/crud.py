from __future__ import unicode_literals

import logging

from bson.json_util import loads
from flask import request, url_for, abort, send_file, make_response
from flask_classy import FlaskView, route
from flask_login import current_user
from mongoengine.errors import InvalidQueryError

from core.database import AttachedFile
from core.helpers import iterify
from core.logger import userLogger
from core.web.api.api import render
from core.web.helpers import get_object_or_404
from core.web.helpers import get_queryset
from core.web.helpers import requires_permissions


class CrudSearchApi(FlaskView):

    def search(self, query):
        fltr = query.get('filter', {})
        params = query.get('params', {})
        regex = params.pop('regex', False)
        ignorecase = params.pop('ignorecase', False)
        page = params.pop('page', 1) - 1
        rng = params.pop('range', 50)        
        userLogger.info("User %s search : filter=%s params=%s regex=%s",
                        current_user.username,fltr,params,regex)
        return list(get_queryset(self.objectmanager, fltr, regex,
                         ignorecase)[page * rng:(page + 1) * rng])

    @requires_permissions('read')
    def post(self):
        """Launches a simple search against the database

        This endpoint is mostly used by paginators in Yeti.

        :<json object params: JSON object specifying the ``page``, ``range`` and ``regex`` variables.
        :<json integer params.page: Page or results to return (default: 1)
        :<json integer params.range: How many results to return (default: 50)
        :<json boolean params.regex: Set to true if the arrays in ``filter`` are to be treated as regular expressions (default: false)
        :<json object filter: JSON object specifying keys to be matched in the database. Each key must contain an array of OR-matched values.

        :reqheader Accept: must be set to ``application/json``
        :reqheader Content-Type: must be set to ``application/json``

        """
        query = request.get_json(silent=True) or {}

        try:
            data = self.search(query)
        except InvalidQueryError as e:
            logging.error(e)
            abort(400)

        return render(data)


class CrudApi(FlaskView):

    template = None
    template_single = None

    @requires_permissions('write')
    def delete(self, id):
        """Deletes the corresponding entry from the database

        :query ObjectID id: Element ID
        :>json string deleted: The deleted element's ObjectID
        """
        obj = get_object_or_404(self.objectmanager, id=id)
        obj.delete()
        return render({"deleted": id})

    @route("/multidelete", methods=['POST'])
    @requires_permissions('write')
    def multidelete(self):
        """Deletes multiple entries from the database

        :query [ObjectID] ids: Array of Element IDs
        :>json [ObjectID] deleted: Array of Element IDs that were successfully deleted
        """
        data = loads(request.data)
        ids = iterify(data['ids'])
        self.objectmanager.objects(id__in=ids).delete()
        return render({"deleted": ids})

    @route("/multiupdate", methods=['POST'])
    @requires_permissions('write')
    def multiupdate(self):
        """Updates multiple entries from the database

        :query [ObjectID] ids: Array of Element IDs
        :query [Object] new: JSON object representing fields to update
        :>json [ObjectID] updated: Array of Element IDs that were successfully updated
        """
        data = loads(request.data)
        ids = iterify(data['ids'])
        new_data = data['new']
        self.objectmanager.objects(id__in=ids).update(new_data)
        return render({
            "updated": list(self.objectmanager.objects(ids__in=ids))
        })

    @requires_permissions('read')
    def index(self):
        """List all corresponding entries in the database. **Do not use on large datasets!**
        """
        objects = [o.info() for o in self.objectmanager.objects.all()]
        return render({'objs':objects})

    # This method can be overridden if needed
    def _parse_request(self, json):
        return json

    @requires_permissions('read')
    def get(self, id):
        """Get details on a specific element

        :query ObjectID id: Element ID
        """
        obj = get_object_or_404(self.objectmanager, id=id)
        return render(obj, self.template_single)

    @route("/", methods=["POST"])
    @requires_permissions('write')
    def new(self):
        """Create a new element

        Create a new element from the JSON object passed in the ``POST`` data.

        :<json object params: JSON object containing fields to set
        """
        params = self._parse_request(request.json)
        objectmanager = self.objectmanager
        if 'type' in params and hasattr(self, 'subobjects'):
            objectmanager = self.subobjects.get(params['type'])
        if objectmanager is None:
            abort(400)
        params.pop('type', None)
        obj = objectmanager(**params).save()
        return render(obj)

    @requires_permissions('write')
    def post(self, id):
        """Modify an element

        Edit an existing element according to the JSON object passed in the ``POST`` data.

        :query ObjectID id: Element ID
        :<json object params: JSON object containing fields to set
        """
        obj = get_object_or_404(self.objectmanager, id=id)
        params = self._parse_request(request.json)
        obj = obj.clean_update(**params)
        return render(obj)

    @route('/<string:id>/files', methods=["GET"])
    @requires_permissions('read')
    def list_files(self, id):
        """List files attached to an element

        :query ObjectID id: Element ID
        :<json object files: JSON object containing a list of serialized AttachedFile objects
        """
        l = []
        entity = get_object_or_404(self.objectmanager, id=id)
        for f in entity.attached_files:
            i = f.info()
            i['content_uri'] = url_for(
                "api.Entity:file_content", sha256=f.sha256)
            l.append(i)
        return render(l)

    @route('/files/<string:sha256>', methods=["GET"])
    @requires_permissions('read')
    def file_content(self, sha256):
        """Get a file's contents

        :query string sha256: The file's SHA-256 hash
        :response object files: Content of files, served as an attachment
        """
        f = get_object_or_404(AttachedFile, sha256=sha256)
        return make_response(
            send_file(
                f.filepath, as_attachment=True, attachment_filename=f.filename))
