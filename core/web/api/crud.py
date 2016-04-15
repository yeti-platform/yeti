import re
import logging

from flask import request, url_for, abort
from flask.ext.classy import FlaskView, route
from mongoengine.errors import InvalidQueryError

from core.web.api.api import render


class CrudSearchApi(FlaskView):

    def search(self, query):
        fltr = query.get('filter', {})
        if 'tags' in fltr:
            fltr["tags__name"] = fltr.pop('tags')
        fltr = {key.replace(".", "__")+"__all": value for key, value in query.get('filter', {}).items()}
        params = query.get('params', {})

        regex = params.pop('regex', False)
        if regex:
            fltr = {key: [re.compile(v) for v in value] for key, value in fltr.items()}

        page = params.pop('page', 1) - 1
        rng = params.pop('range', 50)

        print "[{}] Filter: {}".format(self.__class__.__name__, fltr)

        data = []
        for o in self.objectmanager.objects(**fltr)[page * rng:(page + 1) * rng]:
            o.uri = url_for("api.{}:post".format(self.objectmanager.__name__), id=str(o.id))
            data.append(o)

        return data


    def post(self):
        """Launches a simple search against the database

        This function is used by paginators in Yeti.

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

        This endpoint will create a new element from the JSON object passed in the ``POST`` data.

        :<json object params: JSON object containing fields to set
        """
        params = self._parse_request(request.json)
        obj = self.objectmanager(**params).save()
        obj.uri = url_for("api.{}:post".format(self.__class__.__name__), id=str(obj.id))
        return render(obj)

    def post(self, id):
        """Create a new element

        This endpoint will edit an existing element according to the JSON object passed in the ``POST`` data.

        :query ObjectID id: Element ID
        :<json object params: JSON object containing fields to set
        """
        obj = self.objectmanager.objects.get(id=id)
        params = self._parse_request(request.json)
        obj = obj.clean_update(**params)
        obj.uri = url_for("api.{}:post".format(self.__class__.__name__), id=str(obj.id))
        return render(obj)
