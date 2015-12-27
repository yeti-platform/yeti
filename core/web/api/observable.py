import re

from flask import request, url_for
from flask_restful import abort as restful_abort
from mongoengine.errors import InvalidQueryError

from core.web.api.crud import CrudApi
from core.observables import Observable
from core.web.api.api import render


class ObservableApi(CrudApi):

    @classmethod
    def post(self):
        query = request.get_json(silent=True)
        fltr = query.get('filter', {})
        params = query.get('params', {})

        regex = params.pop('regex', False)
        if regex:
            fltr = {key: re.compile(value) for key, value in fltr.items()}
        page = params.pop('page', 1) - 1
        rng = params.pop('range', 50)

        print "Filter:", fltr
        for key, value in fltr.copy().items():
            if key == 'tags':
                if not regex:
                    fltr['tags__name__in'] = fltr.pop('tags').split(',')
                else:
                    fltr['tags__name'] = fltr.pop('tags')

        try:
            data = []
            for o in self.objectmanager.objects(**fltr)[page * rng:(page + 1) * rng]:
                info = o.info()
                info['uri'] = url_for("api.{}".format(self.__name__.lower()), id=str(o.id))
                data.append(info)

        except InvalidQueryError as e:
            restful_abort(400, invalid_query=str(e))

        return render(data, self.template)

    template = 'observable_api.html'
    objectmanager = Observable
