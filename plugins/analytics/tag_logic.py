from __future__ import unicode_literals
from datetime import timedelta
import logging

from mongoengine import DoesNotExist

from core.analytics import ScheduledAnalytics
from core.observables import Tag
from mongoengine import Q

class TagLogic(ScheduledAnalytics):

    default_values = {
        "frequency": timedelta(minutes=30),
        "name": "TagLogic",
        "description": "Processes some tagging logic",
    }

    ACTS_ON = []  # act on all observables
    EXPIRATION = timedelta(seconds=3)

    def __init__(self, *args, **kwargs):
        super(TagLogic, self).__init__(*args, **kwargs)

        existing_tags = {t.name: (t.replaces, t.produces) for t in Tag.objects.all()}
        all_replacements = {}
        all_produces = {}
        for tag, (replaces, produces) in existing_tags.items():
            for rep in replaces:
                if rep:
                    all_replacements[rep] = tag

            all_produces[tag] = [t.name for t in produces]

        exists = Q(tags__exists=True)
        not_in_existing = Q(tags__name__nin=existing_tags.keys())
        must_replace = Q(tags__name__in=all_replacements.keys())

        self.CUSTOM_FILTER = exists & (not_in_existing | must_replace)

    def bulk(self, observables):
        for o in observables:
            self.each(o)

    @staticmethod
    def each(obj):

        all_tags = set([t.name for t in obj.tags])

        # tag absent produced tags
        for tag in all_tags:
            try:
                db_tag = Tag.objects.get(name=tag)
                produced_tags = db_tag.produces
                obj.tag([t.name for t in produced_tags if t.name not in all_tags])
            except DoesNotExist:
                logging.error("Nonexisting tag: {} (found in {})".format(tag, obj.value))
