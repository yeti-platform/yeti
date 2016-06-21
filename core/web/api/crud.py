from __future__ import unicode_literals

import logging

from bson.json_util import loads
from flask import request, url_for, abort, send_file, make_response
from flask_classy import FlaskView, route
from mongoengine.errors import InvalidQueryError

from core.web.api.api import render
from core.web.helpers import get_queryset
from core.helpers import iterify
from core.database import AttachedFile
from core.web.helpers import get_object_or_404


class CrudSearchApi(FlaskView):
    def search(self, query):
        fltr = query.get('filter', {})
        params = query.get('params', {})
        regex = params.pop('regex', False)
        ignorecase = params.pop('ignorecase', False)
        page = params.pop('page', 1) - 1
        rng = params.pop('range', 50)

        data = []
        for o in get_queryset(self.objectmanager, fltr, regex, ignorecase)[page * rng:(page + 1) * rng]:
            o.uri = url_for("api.{}:post".format(self.objectmanager.__name__), id=str(o.id))
            data.append(o)

        return data

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

        return render(data, self.template)


class CrudApi(FlaskView):

    template = None
    template_single = None

    def delete(self, id):
        """Deletes the corresponding entry from the database

        :query ObjectID id: Element ID
        :>json string deleted: The deleted element's ObjectID
        """
        obj = self.objectmanager.objects.get(id=id)
        obj.delete()
        return render({"deleted": id})

    @route("/multidelete", methods=['POST'])
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
        return render({"updated": list(self.objectmanager.objects(ids__in=ids))})

    def index(self):
        """List all corresponding entries in the database. **Do not use on large datasets!**
        """
        data = []
        for obj in self.objectmanager.objects.all():
            obj.uri = url_for("api.{}:get".format(self.__class__.__name__), id=str(obj.id))
            data.append(obj)
        return render(data, template=self.template)

    # This method can be overridden if needed
    def _parse_request(self, json):
        return json

    def get(self, id):
        """Get details on a specific element

        :query ObjectID id: Element ID
        """
        obj = self.objectmanager.objects.get(id=id)
        obj.uri = url_for("api.{}:get".format(self.__class__.__name__), id=str(obj.id))
        return render(obj, self.template_single)

    @route("/", methods=["POST"])
    def new(self):
        """Create a new element

        Create a new element from the JSON object passed in the ``POST`` data.

        :<json object params: JSON object containing fields to set
        """
        params = self._parse_request(request.json)
        obj = self.objectmanager(**params).save()
        obj.uri = url_for("api.{}:post".format(self.__class__.__name__), id=str(obj.id))
        return render(obj)

    def post(self, id):
        """Modify an element

        Edit an existing element according to the JSON object passed in the ``POST`` data.

        :query ObjectID id: Element ID
        :<json object params: JSON object containing fields to set
        """
        obj = self.objectmanager.objects.get(id=id)
        params = self._parse_request(request.json)
        obj = obj.clean_update(**params)
        obj.uri = url_for("api.{}:post".format(self.__class__.__name__), id=str(obj.id))
        return render(obj)

    @route('/<string:id>/files', methods=["GET"])
    def list_files(self, id):
        """List files attached to an element

        :query ObjectID id: Element ID
        :<json object files: JSON object containing a list of serialized AttachedFile objects
        """
        l = []
        entity = get_object_or_404(self.objectmanager, id=id)
        for f in entity.attached_files:
            i = f.info()
            i['content_uri'] = url_for("api.Entity:file_content", sha256=f.sha256)
            l.append(i)
        print l
        return render(l)

    @route('/files/<string:sha256>', methods=["GET"])
    def file_content(self, sha256):
        """Get a file's contents

        :query string sha256: The file's SHA-256 hash
        :response object files: Content of files, served as an attachment
        """
        f = get_object_or_404(AttachedFile, sha256=sha256)
        return make_response(send_file(f.filepath, as_attachment=True, attachment_filename=f.filename))
