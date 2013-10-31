__author__ = 'pyt'

from Malcom.analytics.analytics import Analytics
from Malcom.celeryctl import celery
from Malcom.feeds.zeustracker import ZeusTrackerBinaries
from Malcom.feeds.zeusgameover import ZeusGameOverDomains
from Malcom.feeds.zeusdropzones import ZeusTrackerDropzones
from Malcom.feeds.zeusconfigs import ZeusTrackerConfigs
from celery.contrib.methods import task_method

@celery.task
def zeustrackerbinaries_tasks():
    ztb = ZeusTrackerBinaries("ZeusTrackerBinaries")
    ztb.analytics = Analytics()
    run =  ztb.update()
    if run is None:
        raise zeustrackerbinaries_tasks.retry(countdown=60)
    return run

@celery.task
def zeustrackergameoverdomains_tasks():
    ztb = ZeusGameOverDomains("ZeusGameOverDomains")
    ztb.analytics = Analytics()
    run =  ztb.update()
    if run is None:
        raise zeustrackergameoverdomains_tasks.retry(countdown=60)
    return run

@celery.task
def zeustrackerdropzones_tasks():
    ztb = ZeusTrackerDropzones("ZeusTrackerDropzones")
    ztb.analytics = Analytics()
    run =  ztb.update()
    if run is None:
        raise zeustrackerdropzones_tasks.retry(countdown=60)
    return run


@celery.task
def zeustrackerconfigs_tasks():
    ztb = ZeusTrackerConfigs("ZeusTrackerConfigs")
    ztb.analytics = Analytics()
    run =  ztb.update()
    if run is None:
        raise zeustrackerconfigs_tasks.retry(countdown=60)
    return run

