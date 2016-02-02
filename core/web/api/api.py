from flask import Blueprint
from flask_restful import Api
from flask.ext.negotiation import Render
from flask.ext.negotiation.renderers import renderer, template_renderer
from json import dumps

from core.web.json import to_json

api = Blueprint("api", __name__, template_folder="templates")
api_restful = Api(api)


@renderer('application/json')
def bson_renderer(data, template=None, ctx=None):
    return dumps(data, default=to_json)

render = Render(renderers=[template_renderer, bson_renderer])
render_json = Render(renderers=[bson_renderer])

from core.web.api.observable import ObservableSearchApi, ObservableApi
from core.web.api.entity import EntityApi, EntitySearchApi
from core.web.api.tag import TagApi, TagActionApi
from core.web.api.analytics import ScheduledAnalyticsApi, OneShotAnalyticsApi
from core.web.api.feeds import FeedApi
from core.web.api.export import ExportApi
from core.web.api.neighbors import NeighborsApi
from core.web.api.investigation import InvestigationApi
from core.web.api.indicator import IndicatorApi, IndicatorSearchApi

api_restful.add_resource(ScheduledAnalyticsApi, '/analytics/scheduled', '/analytics/scheduled/<string:id>/<string:action>')
api_restful.add_resource(OneShotAnalyticsApi, '/analytics/oneshot', '/analytics/oneshot/<string:id>/<string:action>')

api_restful.add_resource(ObservableSearchApi, '/observables/search')
api_restful.add_resource(ObservableApi, '/observables/', '/observables/<string:id>')

api_restful.add_resource(IndicatorSearchApi, '/indicators/search')
api_restful.add_resource(IndicatorApi, '/indicators/', '/indicators/<string:id>')

api_restful.add_resource(EntitySearchApi, '/entities/search')
api_restful.add_resource(EntityApi, '/entities/', '/entities/<string:id>')


api_restful.add_resource(TagApi, '/tags/', '/tags/<string:id>', "/tags/<string:action>")
api_restful.add_resource(TagActionApi, '/tags/action/<string:action>')

api_restful.add_resource(FeedApi, '/feeds/', '/feeds/<string:id>/<string:action>')
api_restful.add_resource(ExportApi, '/exports/', '/exports/<string:id>', '/exports/<string:id>/<string:action>')

api_restful.add_resource(NeighborsApi, '/neighbors/<string:klass>/<string:node_id>')

api_restful.add_resource(InvestigationApi, '/investigations/', '/investigations/<string:id>', '/investigations/<string:id>/<string:action>')
