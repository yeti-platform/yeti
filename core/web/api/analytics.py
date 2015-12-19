from core.web.api.crud import CrudApi
from core.analytics import ScheduledAnalytics, OneShotAnalytics
from core.analytics_tasks import schedule
from core.web.api.api import render


class ScheduledAnalyticsApi(CrudApi):
    template = 'scheduled_analytics_api.html'
    objectmanager = ScheduledAnalytics

    def post(self, name, action):
        if action == "refresh":
            schedule.delay(name)
            return render({"name": name})
        if action == "toggle":
            a = ScheduledAnalytics.objects.get(name=name)
            a.enabled = not a.enabled
            a.save()
            return render({"name": name, "status": a.enabled})


class OneShotAnalyticsApi(CrudApi):
    template = "oneshot_analytics_api.html"
    objectmanager = OneShotAnalytics

    def post(self, name, action):
        if action == "toggle":
            a = OneShotAnalytics.objects.get(name=name)
            a.enabled = not a.enabled
            a.save()
            return render({"name": name, "status": a.enabled})
