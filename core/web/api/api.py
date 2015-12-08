from flask import Blueprint
from flask_restful import Api
from flask.ext.negotiation import Render
from flask.ext.negotiation.renderers import renderer, template_renderer
from bson.json_util import dumps

api = Blueprint("api", __name__, template_folder="templates")
api_restful = Api(api)


@renderer('application/json')
def bson_renderer(data, template=None, ctx=None):
    return dumps(data)

render = Render(renderers=[template_renderer, bson_renderer])

from core.web.api.observable import ObservableApi
from core.web.api.analysis import AnalysisApi

api_restful.add_resource(AnalysisApi, '/analysis/')
api_restful.add_resource(ObservableApi, '/observables/')
