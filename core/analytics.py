from datetime import datetime

from core.config.celeryctl import celery_app
from core.scheduling import ScheduleEntry, OneShotEntry
from core.observables import Observable
from core.user import User
from core.helpers import iterify
from mongoengine import *


class ScheduledAnalytics(ScheduleEntry):
    """Base class for analytics. All analytics must inherit from this"""

    SCHEDULED_TASK = 'core.analytics_tasks.schedule'
    CUSTOM_FILTER = Q()

    def analyze_outdated(self):
        class_filter = Q()
        for acts_on in iterify(self.ACTS_ON):
            class_filter |= Q(_cls="Observable.{}".format(acts_on))

        # do outdated logic
        fltr = Q(**{"last_analyses__{}__exists".format(self.name): False})
        if self.EXPIRATION:
            fltr |= Q(**{"last_analyses__{}__lte".format(self.name): datetime.utcnow() - self.EXPIRATION})
        fltr &= self.CUSTOM_FILTER & class_filter
        self.bulk(Observable.objects(fltr).no_cache())

    def bulk(self, elts):
        """Bulk analytics. May be overridden in case the module needs to batch-analyze observables"""
        for e in elts:
            celery_app.send_task("core.analytics_tasks.each", [str(self.id), e.to_json()])

    @classmethod
    def each(cls, observable):
        raise NotImplementedError("This method must be overridden in each class it inherits from")

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["name", "description", "last_run", "enabled", "status"]}
        i['frequency'] = str(self.frequency)
        i['expiration'] = str(self.EXPIRATION)
        i['acts_on'] = iterify(self.ACTS_ON)
        i['id'] = str(self.id)
        return i


class AnalyticsResults(Document):
    analytics = ReferenceField('OneShotAnalytics', required=True)
    observable = ReferenceField('Observable', required=True)
    status = StringField()
    results = ListField(ReferenceField('Link'))
    settings = DictField()
    raw = StringField()
    error = StringField()


class OneShotAnalytics(OneShotEntry):

    def __init__(self, *args, **kwargs):
        super(OneShotAnalytics, self).__init__(*args, **kwargs)

        if hasattr(self, 'settings'):
            for setting_id, setting in self.settings.iteritems():
                User.register_setting(setting_id, setting['name'], setting['description'])

    def run(self, e, settings):
        results = AnalyticsResults(analytics=self, observable=e, status='pending', settings=settings).save()
        celery_app.send_task("core.analytics_tasks.single", [str(results.id)])

        return results

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["name", "description", "enabled"]}
        i['acts_on'] = iterify(self.ACTS_ON)
        i['id'] = str(self.id)
        return i
