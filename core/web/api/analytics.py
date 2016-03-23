from flask.ext.login import current_user
from flask.ext.classy import route
from flask import request

from core.observables import Observable
from core.web.api.crud import CrudApi
from core import analytics
from core.analytics_tasks import schedule
from core.web.api.api import render
from core.web.helpers import get_object_or_404


class ScheduledAnalytics(CrudApi):
    template = 'scheduled_analytics_api.html'
    objectmanager = analytics.ScheduledAnalytics

    @route("/<id>/refresh", methods=["POST"])
    def refresh(self, id):
        schedule.delay(id)
        return render({"id": id})

    @route("/<id>/toggle", methods=["POST"])
    def toggle(self, id):
        a = self.objectmanager.objects.get(id=id)
        a.enabled = not a.enabled
        a.save()

        return render({"id": id, "status": a.enabled})


class OneShotAnalytics(CrudApi):
    template = "oneshot_analytics_api.html"
    objectmanager = analytics.OneShotAnalytics

    def index(self):
        data = []

        for obj in self.objectmanager.objects.all():
            info = obj.info()

            info['available'] = True
            if hasattr(obj, 'settings') and not current_user.has_settings(obj.settings):
                info['available'] = False

            data.append(info)

        return render(data, template=self.template)

    @route("/<id>/toggle", methods=["POST"])
    def toggle(self, id):
        analytics = get_object_or_404(self.objectmanager, id=id)
        analytics.enabled = not analytics.enabled
        analytics.save()

        return render({"id": analytics.id, "status": analytics.enabled})

    @route('/<id>/run', methods=["POST"])
    def run(self, id):
        analytics = get_object_or_404(self.objectmanager, id=id)
        observable = get_object_or_404(Observable, id=request.form.get('id'))

        return render(analytics.run(observable, current_user.settings).to_mongo())

    @route('/<id>/status')
    def status(self, id):
        results = get_object_or_404(analytics.AnalyticsResults, id=id)

        nodes_id = set()
        nodes = list()
        links = list()

        # First, add the analyzed node
        nodes_id.add(results.observable.id)
        nodes.append(results.observable.to_mongo())

        for link in results.results:
            for node in (link.src, link.dst):
                if node.id not in nodes_id:
                    nodes_id.add(node.id)
                    nodes.append(node.to_mongo())
            links.append(link.to_dict())

        results = results.to_mongo()
        results['results'] = {'nodes': nodes, 'links': links}

        return render(results)
