from datetime import datetime
import logging

from core.config.celeryctl import celery_app
from core.observables import Observable
from core.config.celeryimports import loaded_modules
from core.analytics import ScheduledAnalytics, OneShotAnalytics


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
    a = ScheduledAnalytics.objects.get(name=name)
    a.analyze_outdated()
    a.last_run = datetime.now()
    a.save()


@celery_app.task
def single(name, observable_json):
    o = Observable.from_json(observable_json)
    logging.warning("Running one-shot query {} on {}".format(name, o))
    a = OneShotAnalytics.objects.get(name=name)
    a.analyze(o)
