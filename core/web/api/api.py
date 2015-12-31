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
from core.web.api.entity import EntityApi
from core.web.api.tag import TagApi, TagActionApi
from core.web.api.analytics import ScheduledAnalyticsApi, OneShotAnalyticsApi
from core.web.api.analysis import AnalysisApi
from core.web.api.feeds import FeedApi
from core.web.api.export import ExportApi

api_restful.add_resource(AnalysisApi, '/analysis/')

api_restful.add_resource(ScheduledAnalyticsApi, '/analytics/scheduled', '/analytics/scheduled/<string:name>/<string:action>')
api_restful.add_resource(OneShotAnalyticsApi, '/analytics/oneshot', '/analytics/oneshot/<string:name>/<string:action>')

api_restful.add_resource(ObservableApi, '/observables/', '/observables/<string:id>')
api_restful.add_resource(EntityApi, '/entities/', '/entities/<string:id>')

api_restful.add_resource(TagApi, '/tags/', '/tags/<string:id>', "/tags/<string:action>")
api_restful.add_resource(TagActionApi, '/tags/action/<string:action>')

api_restful.add_resource(FeedApi, '/feeds/', '/feeds/<string:id>/<string:action>')
api_restful.add_resource(ExportApi, '/exports/', '/exports/<string:id>', '/exports/<string:id>/<string:action>')
