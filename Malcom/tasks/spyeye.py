__author__ = 'pyt'

from Malcom.analytics.analytics import Analytics
from Malcom.celeryctl import celery
from Malcom.feeds.spyeyebinaries import SpyEyeBinaries
from Malcom.feeds.spyeyeconfigs import SpyEyeConfigs
from Malcom.feeds.spyeyedropzones import SpyEyeDropzones
from Malcom.feeds.spyeyecnc import SpyEyeCnc


@celery.task
def spyeyebinaries_tasks():
    se = SpyEyeBinaries("SpyEyeBinaries")
    se.analytics = Analytics()
    run =  se.update()
    if run is None:
        raise spyeyebinaries_tasks.retry(countdown=60)
    return run

@celery.task
def spyeyeconfigs_tasks():
    se = SpyEyeConfigs("SpyEyeConfigs")
    se.analytics = Analytics()
    run =  se.update()
    if run is None:
        raise spyeyeconfigs_tasks.retry(countdown=60)
    return run


@celery.task
def spyeyedropzones_tasks():
    se = SpyEyeDropzones("SpyEyeDropzones")
    se.analytics = Analytics()
    run =  se.update()
    if run is None:
        raise spyeyedropzones_tasks.retry(countdown=60)
    return run

@celery.task
def spyeyecnc_tasks():
    se = SpyEyeCnc("SpyEyeCnc")
    se.analytics = Analytics()
    run =  se.update()
    if run is None:
        raise spyeyecnc_tasks.retry(countdown=60)
    return run
