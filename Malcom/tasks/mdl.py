__author__ = 'pyt'

from Malcom.analytics.analytics import Analytics
from Malcom.celeryctl import celery
from Malcom.feeds.mdlhostlist import MDLHosts
from Malcom.feeds.mdliplist import MDLIpList
from Malcom.feeds.mdltracker import MDLTracker


@celery.task
def mdlhosts_tasks():
    mdl = MDLHosts("MDLHosts")
    mdl.analytics = Analytics()
    run =  mdl.update()
    if run is None:
        raise mdlhosts_tasks.retry(countdown=60)
    return run

@celery.task
def mdliplist_tasks():
    mdl = MDLIpList("MDLIpList")
    mdl.analytics = Analytics()
    run =  mdl.update()
    if run is None:
        raise mdliplist_tasks.retry(countdown=60)
    return run

@celery.task
def mdltracker_tasks():
    mdl = MDLTracker("MDLTracker")
    mdl.analytics = Analytics()
    run =  mdl.update()
    if run is None:
        raise mdliplist_tasks.retry(countdown=60)
    return run
