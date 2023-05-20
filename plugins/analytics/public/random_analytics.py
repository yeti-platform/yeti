from datetime import timedelta

from core import taskmanager
from core.schemas import task
# from core.analytics import ScheduledAnalytics
# from mongoengine import Q


class PrintDomains(task.AnalyticsTask):
    _defaults = {
        "frequency": timedelta(hours=12),
        "type": "analytics",
        "description": "Extracts a domain from a URL",
    }

    acts_on: list[str] = ['hostname']  # act on all observables

    # TODO Use server-side JS filter
    # CUSTOM_FILTER = Q(tags__not__size=0)  # filter only tagged elements

    # def bulk(self, observables):
    #     for o in observables:
    #         self.each(o)

    def each(self, observable):
        print(observable.value)


taskmanager.TaskManager.register_task(PrintDomains)
