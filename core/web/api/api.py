from __future__ import unicode_literals

import logging

from functools import wraps

from flask import Blueprint, request
from flask_negotiation import Render
from flask_negotiation.renderers import renderer, template_renderer
from json import dumps

from core.web.json import to_json, recursive_encoder
from core.config.config import yeti_config

api = Blueprint("api", __name__, template_folder="templates")

def check_accept_header():
    """Added as a before_request() handler to log 'Accept: */*'"""
    if request.headers.get('Accept','').lower() in ('application/json','text/html'):
        return
    logging.warn('Request for {} with Accept: other than application/json or text/html: {}'.format(
                    request.base_url, request.headers.get('Accept','Not provided')
                ))
    return

api.before_request(check_accept_header)

# If you're querying Yeti's API from another app,
# these lines might be useful:
#
# from flask_cors import CORS, cross_origin
# CORS(api, resources={r"*": {"origins": "*"}})

@renderer('application/json')
def bson_renderer(objects, template=None, ctx=None):
    data = recursive_encoder(objects)
    return dumps(data, default=to_json)

# This is waaaaay complicated internally, but in the case where the same requested
# media type matches for multiple renderers (which is the case when the (only) media
# type is 'Accept: */*') then the earliest one in the list takes precedence.
if yeti_config.api.json_first:
    render = Render(renderers=[bson_renderer, template_renderer])       # JSON first
else:
    render = Render(renderers=[template_renderer, bson_renderer])       # HTML first
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
