from flask import Blueprint
from flask.ext.negotiation import Render
from flask.ext.negotiation.renderers import renderer, template_renderer
from json import dumps

from core.web.json import to_json
from core.helpers import iterify
from core.database import Node, Link


api = Blueprint("api", __name__, template_folder="templates")


@renderer('application/json')
def bson_renderer(objects, template=None, ctx=None):
    data = recursive_encoder(objects)
    return dumps(data, default=to_json)


def recursive_encoder(objects, template=None, ctx=None):

    if isinstance(objects, dict):
        for (key, value) in objects.items():
            objects[key] = recursive_encoder(value)
        return objects

    elif isinstance(objects, list):
        return [recursive_encoder(o) for o in objects]

    elif isinstance(objects, tuple):
        return tuple(recursive_encoder(o) for o in objects)

    elif isinstance(objects, (Node, Link)):
        data = []
        for o in iterify(objects):
            info = o.info()
            if hasattr(o, 'uri'):
                info['uri'] = o.uri
            data.append(info)

        if len(data) == 1:
            data = data[0]

        return data
    else:
        return objects


render = Render(renderers=[template_renderer, bson_renderer])
render_json = Render(renderers=[bson_renderer])

from core.web.api.observable import ObservableSearch, Observable
from core.web.api.entity import Entity, EntitySearch
from core.web.api.tag import Tag
from core.web.api.analytics import ScheduledAnalytics, OneShotAnalytics
from core.web.api.analysis import Analysis
from core.web.api.feeds import Feed
from core.web.api.export import Export, ExportTemplate
from core.web.api.neighbors import Neighbors
from core.web.api.investigation import Investigation
from core.web.api.indicator import Indicator, IndicatorSearch

Analysis.register(api)

ScheduledAnalytics.register(api, route_base='/analytics/scheduled')
OneShotAnalytics.register(api, route_base='/analytics/oneshot')

ObservableSearch.register(api)
Observable.register(api)

IndicatorSearch.register(api)
Indicator.register(api)

EntitySearch.register(api)
Entity.register(api)

Tag.register(api)

Feed.register(api)
Export.register(api)
ExportTemplate.register(api)

Neighbors.register(api)

Investigation.register(api)
