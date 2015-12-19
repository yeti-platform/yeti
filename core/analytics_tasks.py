from datetime import datetime
import logging

from core.config.celeryctl import celery_app
from core.observables import Observable
from core.config.celeryimports import loaded_modules
from core.analytics import ScheduledAnalytics, OneShotAnalytics

from mongoengine import DoesNotExist


@celery_app.task
def each(module_name, observable_json):
    o = Observable.from_json(observable_json)
    logging.warning("Launching {} on {}".format(module_name, o))
    mod = loaded_modules[module_name]
    mod.each(o)
    o.analysis_done(module_name)


@celery_app.task
def schedule(name):
    logging.warning("Running analytics {}".format(name))

    try:
        a = ScheduledAnalytics.objects.get(name=name, lock=None)  # check if we have implemented locking mechanisms
    except DoesNotExist:
        try:
            ScheduledAnalytics.objects.get(name=name, lock=False).modify(lock=True)  # get object and change lock
            a = ScheduledAnalytics.objects.get(name=name)
        except DoesNotExist:
            # no unlocked ScheduledAnalytics was found, notify and return...
            logging.info("Task {} is already running...".format(name))
            return

    a.update_status("Running...")
    if a.enabled:  # check if Analytics is enabled
        a.analyze_outdated()
        a.last_run = datetime.now()

    if a.lock:  # release lock if it was set
        a.lock = False

    a.save()
    a.update_status("OK")


@celery_app.task
def single(name, observable_json):
    o = Observable.from_json(observable_json)
    logging.warning("Running one-shot query {} on {}".format(name, o))
    a = OneShotAnalytics.objects.get(name=name)
    a.analyze(o)
