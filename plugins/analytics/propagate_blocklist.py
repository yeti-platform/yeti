from __future__ import unicode_literals
from datetime import timedelta

from core.analytics import ScheduledAnalytics
from mongoengine import Q


class PropagateBlocklist(ScheduledAnalytics):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "PropagateBlocklist",
        "description": "Expires tags in observables",
    }

    ACTS_ON = 'Url'  # act on Urls only

    CUSTOM_FILTER = Q(tags__not__size=0)  # filter only tagged elements

    EXPIRATION = None

    @staticmethod
    def each(obj):
        if obj.has_tag("blocklist"):
            n = obj.neighbors(neighbor_type="Hostname").values()
            if n:
                for link in n[0]:
                    link[1].tag('blocklist')
