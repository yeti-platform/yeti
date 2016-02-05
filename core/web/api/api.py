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
from core.web.api.tag import TagApi
from core.web.api.analytics import ScheduledAnalyticsApi, OneShotAnalyticsApi
from core.web.api.feeds import FeedApi
from core.web.api.export import ExportApi, ExportTemplateApi
from core.web.api.neighbors import NeighborsApi
from core.web.api.investigation import InvestigationApi
from core.web.api.indicator import IndicatorApi, IndicatorSearchApi

ScheduledAnalyticsApi.register(api)
OneShotAnalyticsApi.register(api, route_base='/analytics/oneshot')

ObservableSearchApi.register(api)
ObservableApi.register(api)

IndicatorSearchApi.register(api)
IndicatorApi.register(api)

EntitySearchApi.register(api)
EntityApi.register(api)

TagApi.register(api)

FeedApi.register(api)
ExportApi.register(api)
ExportTemplateApi.register(api)

NeighborsApi.register(api, route_base='/neighbors')

InvestigationApi.register(api, route_base='/investigations')
