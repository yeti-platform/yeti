from datetime import datetime
import logging

from core.config.celeryctl import celery_app
from core.datatypes import Element
from core.config.celeryimports import loaded_modules
from core.analytics import ScheduledAnalytics, OneShotAnalytics


@celery_app.task
def each(module_name, element_json):
    e = Element.from_json(element_json)
    logging.warning("Launching {} on {}".format(module_name, e))
    mod = loaded_modules[module_name]
    mod.each(e)
    e.analysis_done(module_name)


@celery_app.task
def schedule(name):
    logging.warning("Running analytics {}".format(name))
    a = ScheduledAnalytics.objects.get(name=name)
    a.analyze_outdated()
    a.last_run = datetime.now()
    a.save()


@celery_app.task
def single(name, element_json):
    element = Element.from_json(element_json)
    logging.warning("Running one-shot query {} on {}".format(name, element))
    a = OneShotAnalytics.objects.get(name=name)
    a.analyze(element)
