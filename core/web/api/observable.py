from flask import request, url_for
from flask_restful import abort as restful_abort
from mongoengine.errors import InvalidQueryError

from core.web.api.crud import CrudApi
from core.observables import Observable
from core.web.api.api import render



class ObservableApi(CrudApi):

    @classmethod
    def post(cls):
        query = request.get_json(silent=True)
        fltr = query.get('filter', {})
        params = query.get('params', {})

        if params.pop('regex', False):
            fltr = {key: re.compile(value) for key, value in fltr.items()}
        page = params.pop('page', 1) - 1
        rng = params.pop('range', 50)

        print "Filter:", fltr

        try:
            data = []
            for o in cls.objectmanager.objects(**fltr)[page * rng:(page + 1) * rng]:
                info = o.info()
                info['uri'] = url_for("api.{}".format(cls.__name__.lower()), id=str(o.id))
                data.append(info)

        except InvalidQueryError as e:
            restful_abort(400, invalid_query=str(e))

        return render(data, cls.template)

    template = 'observable_api.html'
    objectmanager = Observable
