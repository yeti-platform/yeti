from __future__ import unicode_literals

from datetime import datetime
import logging
import traceback

from core.config.celeryctl import celery_app
from core.observables import Observable
from core.config.celeryimports import loaded_modules
from core.analytics import ScheduledAnalytics, AnalyticsResults

from mongoengine import DoesNotExist

@celery_app.task
def each(module_id, observable_json):
    o = Observable.from_json(observable_json)
    mod = loaded_modules[module_id]
    logging.debug("Launching {} on {}".format(mod.__class__.__name__, o))
    mod.each(o)
    o.analysis_done(mod.__class__.__name__)


@celery_app.task
def schedule(id):

    try:
        a = ScheduledAnalytics.objects.get(id=id, lock=None)  # check if we have implemented locking mechanisms
    except DoesNotExist:
        try:
            ScheduledAnalytics.objects.get(id=id, lock=False).modify(lock=True)  # get object and change lock
            a = ScheduledAnalytics.objects.get(id=id)
        except DoesNotExist:
            # no unlocked ScheduledAnalytics was found, notify and return...
            logging.debug("Task {} is already running...".format(ScheduledAnalytics.objects.get(id=id).name))
            return

    if a.enabled:  # check if Analytics is enabled
        logging.debug("Running analytics {}".format(a.name))
        a.update_status("Running...")
        a.analyze_outdated()
        a.last_run = datetime.utcnow()
    else:
        logging.debug("Analytics {} is disabled".format(a.name))

    if a.lock:  # release lock if it was set
        a.lock = False

    a.save()
    a.update_status("OK")


@celery_app.task
def single(results_id):
    results = AnalyticsResults.objects.get(id=results_id)
    analytics = results.analytics
    logging.debug("Running one-shot query {} on {}".format(analytics.__class__.__name__, results.observable))
    results.update(status="running")
    try:
        links = analytics.analyze(results.observable, results)
        results.update(status="finished", results=links)
    except Exception, e:
        results.update(status="error", error=str(e))
        traceback.print_exc()

    results.observable.analysis_done(analytics.__class__.__name__)
