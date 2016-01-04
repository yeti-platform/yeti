import datetime
from flask import Blueprint
from flask_restful import Api
from flask.ext.negotiation import Render
from flask.ext.negotiation.renderers import renderer, template_renderer
from json import dumps
from bson.json_util import default
from bson.objectid import ObjectId
from bson.dbref import DBRef


api = Blueprint("api", __name__, template_folder="templates")
api_restful = Api(api)


def to_json(obj):
    if isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, DBRef):
        d = obj.as_doc()
        return {'cls': d['cls'], 'id': str(d['$id'])}
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return default(obj)


@renderer('application/json')
def bson_renderer(data, template=None, ctx=None):
    return dumps(data, default=to_json)

render = Render(renderers=[template_renderer, bson_renderer])
render_json = Render(renderers=[bson_renderer])

from core.web.api.observable import ObservableSearchApi, ObservableApi
from core.web.api.entity import EntityApi
from core.web.api.tag import TagApi, TagActionApi
from core.web.api.analytics import ScheduledAnalyticsApi, OneShotAnalyticsApi
from core.web.api.analysis import AnalysisApi
from core.web.api.feeds import FeedApi
from core.web.api.export import ExportApi
from core.web.api.graph import GraphNeighborsApi

api_restful.add_resource(AnalysisApi, '/analysis/')

api_restful.add_resource(ScheduledAnalyticsApi, '/analytics/scheduled', '/analytics/scheduled/<string:name>/<string:action>')
api_restful.add_resource(OneShotAnalyticsApi, '/analytics/oneshot', '/analytics/oneshot/<string:name>/<string:action>')

api_restful.add_resource(ObservableSearchApi, '/observables/search')
api_restful.add_resource(ObservableApi, '/observables/', '/observables/<string:id>')

api_restful.add_resource(EntityApi, '/entities/', '/entities/<string:id>')

api_restful.add_resource(TagApi, '/tags/', '/tags/<string:id>', "/tags/<string:action>")
api_restful.add_resource(TagActionApi, '/tags/action/<string:action>')

api_restful.add_resource(FeedApi, '/feeds/', '/feeds/<string:id>/<string:action>')
api_restful.add_resource(ExportApi, '/exports/', '/exports/<string:id>', '/exports/<string:id>/<string:action>')

api_restful.add_resource(GraphNeighborsApi, '/graph/neighbors/<string:node_id>')
