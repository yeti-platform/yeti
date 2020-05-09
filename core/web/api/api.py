from __future__ import unicode_literals

from json import dumps

from flask import Blueprint, jsonify, render_template, request
from flask_api.decorators import set_renderers
from flask_api.renderers import JSONRenderer

from core.web.json import to_json, recursive_encoder

api = Blueprint("api", __name__, template_folder="templates")

# If you're querying Yeti's API from another app,
# these lines might be useful:
#
# from flask_cors import CORS, cross_origin
# CORS(api, resources={r"*": {"origins": "*"}}, expose_headers=['content-disposition'])

def bson_renderer(objects, template=None, ctx=None):
    data = recursive_encoder(objects)
    return dumps(data, default=to_json)

@set_renderers(JSONRenderer)
def render(obj, template=None):
    mimetypes = request.accept_mimetypes
    best = mimetypes.best_match(['text/html', 'application/json'], 'application/json')
    if best == 'application/json':
        json_obj = recursive_encoder(obj)
        return jsonify(json_obj)
    return render_template(template, data=obj)

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
from core.web.api.useradmin import UserAdminSearch, UserAdmin
from core.web.api.groupadmin import GroupAdminSearch, GroupAdmin


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
UserAdmin.register(api)
GroupAdminSearch.register(api)
GroupAdmin.register(api)
