from __future__ import unicode_literals

from datetime import datetime

from mongoengine import *
from mongoengine import signals

from core.config.celeryctl import celery_app
from core.database import YetiDocument
from core.helpers import iterify
from core.observables import Observable
from core.scheduling import ScheduleEntry, OneShotEntry
from core.user import User


class AnalyticsResults(Document):
    analytics = ReferenceField("OneShotAnalytics", required=True)
    observable = ReferenceField("Observable", required=True)
    status = StringField()
    results = ListField(ReferenceField("Link"))
    settings = DictField()
    raw = StringField()
    error = StringField()
    datetime = DateTimeField(default=datetime.utcnow)


class InlineAnalytics(YetiDocument):
    name = StringField(required=True, unique=True)
    enabled = BooleanField(default=True)
    description = StringField()

    ACTS_ON = []
    default_values = None
    analytics = {}

    meta = {"allow_inheritance": True}

    def __init__(self, *args, **kwargs):
        YetiDocument.__init__(self, *args, **kwargs)

        InlineAnalytics.analytics[self.name] = self

    @staticmethod
    def each(observable):
        raise NotImplementedError(
            "This method must be overridden in each class it inherits from"
        )

    def info(self):
        i = {
            k: v
            for k, v in self._data.items()
            if k in ["name", "description", "enabled"]
        }
        i["acts_on"] = iterify(self.ACTS_ON)
        i["id"] = str(self.id)
        return i

    @classmethod
    def post_save(cls, sender, document, created):
        if issubclass(sender, Observable):
            if getattr(document, "new", False):
                for analytics in cls.analytics.values():
                    if analytics.enabled and sender.__name__ in iterify(
                        analytics.ACTS_ON
                    ):
                        document.new = False
                        analytics.each(document)


signals.post_save.connect(InlineAnalytics.post_save)


class ScheduledAnalytics(ScheduleEntry):
    """Base class for analytics. All analytics must inherit from this"""

    SCHEDULED_TASK = "core.analytics_tasks.schedule"
    CUSTOM_FILTER = Q()

    def analyze_outdated(self):
        class_filter = Q()
        for acts_on in iterify(self.ACTS_ON):
            class_filter |= Q(_cls="Observable.{}".format(acts_on))

        # do outdated logic
        fltr = Q(**{"last_analyses__{}__exists".format(self.name): False})
        if self.EXPIRATION:
            fltr |= Q(
                **{
                    "last_analyses__{}__lte".format(self.name): datetime.utcnow()
                    - self.EXPIRATION
                }
            )
        fltr &= self.CUSTOM_FILTER & class_filter
        self.bulk(Observable.objects(fltr).no_cache())

    def bulk(self, elts):
        """Bulk analytics. May be overridden in case the module needs to batch-analyze observables"""
        for e in elts:
            celery_app.send_task(
                "core.analytics_tasks.each", [str(self.name), e.to_json()]
            )

    @classmethod
    def each(cls, observable):
        raise NotImplementedError(
            "This method must be overridden in each class it inherits from"
        )

    def info(self):
        i = {
            k: v
            for k, v in self._data.items()
            if k in ["name", "description", "last_run", "enabled", "status"]
        }
        i["frequency"] = str(self.frequency)
        i["expiration"] = str(self.EXPIRATION)
        i["acts_on"] = iterify(self.ACTS_ON)
        i["id"] = str(self.id)
        return i


class OneShotAnalytics(OneShotEntry):
    group = StringField(default="")

    def __init__(self, *args, **kwargs):
        super(OneShotAnalytics, self).__init__(*args, **kwargs)

        if hasattr(self, "settings"):
            for setting_id, setting in self.settings.items():
                User.register_setting(
                    setting_id, setting["name"], setting["description"]
                )

    def run(self, e, settings):
        results = AnalyticsResults(
            analytics=self, observable=e, status="pending", settings=settings
        ).save()
        celery_app.send_task("core.analytics_tasks.single", [str(results.id)])

        return results

    def info(self):
        i = {
            k: v
            for k, v in self._data.items()
            if k in ["name", "description", "enabled", "group"]
        }
        i["acts_on"] = iterify(self.ACTS_ON)
        i["id"] = str(self.id)
        return i
