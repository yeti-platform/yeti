from datetime import datetime

from core.config.celeryctl import celery_app
from core.datatypes import Element
from core.config.celeryimports import loaded_modules
from core.analytics import Analytics

@celery_app.task
def each(module_name, element_json):
    e = Element.from_json(element_json)
    print "Launching {} on {}".format(module_name, e)
    mod = loaded_modules[module_name]
    mod.each(e)
    e.analysis_done(module_name)

@celery_app.task
def schedule(name):
    print "Running analytics {}".format(name)
    a = Analytics.objects.get(name=name)
    a.analyze_outdated()
    a.last_run = datetime.now()
    a.save()
