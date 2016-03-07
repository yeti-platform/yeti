from __future__ import unicode_literals
from datetime import timedelta

from core.analytics import ScheduledAnalytics
from mongoengine import Q


class ExpireTags(ScheduledAnalytics):

    default_values = {
        "frequency": timedelta(hours=12),
        "name": "ExpireTags",
        "description": "Expires tags in observables",
    }

    ACTS_ON = []  # act on all observables

    # TODO Use server-side JS filter
    CUSTOM_FILTER = Q(tags__not__size=0)  # filter only tagged elements

    EXPIRATION = timedelta(days=1)

    @staticmethod
    def each(obj):
        obj.expire_tags()
