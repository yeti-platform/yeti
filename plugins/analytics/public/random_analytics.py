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

    def each(self, observable):
        print(observable.value)

class PrintDomain(task.OneShotTask):
    _defaults = {
        "type": "oneshot",
        "description": "Just prints an observable's value",
    }

    acts_on: list[str] = ['hostname']

    def each(self, observable):
        print(observable.value)

taskmanager.TaskManager.register_task(PrintDomains)
taskmanager.TaskManager.register_task(PrintDomain)
