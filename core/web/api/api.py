from __future__ import unicode_literals

from flask import Blueprint
from flask_negotiation import Render
from flask_negotiation.renderers import renderer, template_renderer
from json import dumps

from core.web.json import to_json, recursive_encoder

api = Blueprint("api", __name__, template_folder="templates")

# If you're querying Yeti's API from another app,
# these lines might be useful:
#
# from flask_cors import CORS, cross_origin
# CORS(api, resources={r"*": {"origins": "*"}})


@renderer('application/json')
def bson_renderer(objects, template=None, ctx=None):
    data = recursive_encoder(objects)
    return dumps(data, default=to_json)


render = Render(renderers=[template_renderer, bson_renderer])
render_json = Render(renderers=[bson_renderer])

from core.web.api.observable import ObservableSearch, Observable
from core.web.api.entity import Entity, EntitySearch
from core.web.api.tag import Tag
from core.web.api.analytics import ScheduledAnalytics, OneShotAnalytics, InlineAnalytics
from core.web.api.analysis import Analysis
from core.web.api.feeds import Feed
from core.web.api.export import Export, ExportTemplate
from core.web.api.neighbors import Neighbors
from core.web.api.investigation import Investigation, InvestigationSearch
from core.web.api.indicator import Indicator, IndicatorSearch
from core.web.api.links import Link
from core.web.api.attached_files import AttachedFiles
from core.web.api.file import File
from core.web.api.useradmin import UserAdminSearch
from core.web.api.groupadmin import GroupAdminSearch


Analysis.register(api)

ScheduledAnalytics.register(api, route_base='/analytics/scheduled')
OneShotAnalytics.register(api, route_base='/analytics/oneshot')
InlineAnalytics.register(api, route_base='/analytics/inline')

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
InvestigationSearch.register(api)

Link.register(api)

AttachedFiles.register(api)
File.register(api)

UserAdminSearch.register(api)
GroupAdminSearch.register(api)
