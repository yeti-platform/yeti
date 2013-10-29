__author__ = 'pyt'

from Malcom.feeds.alienvault import AlienvaultIP
from Malcom.feeds.dshield_as16276 import DShield16276
from Malcom.feeds.dshield_as3215 import DShield3215
from Malcom.feeds.malcode import MalcodeBinaries
from Malcom.feeds.malwarepatrol import MalwarePatrolVX
from Malcom.feeds.openbl import OpenblIP
from Malcom.feeds.palevotracker import PalevoTracker
from Malcom.feeds.siri_urz import SiriUrzVX
from Malcom.feeds.suspiciousdomains import SuspiciousDomains
from Malcom.feeds.torexitnodes import TorExitNodes
from Malcom.analytics.analytics import Analytics
from Malcom.celeryctl import celery


@celery.task
def alienvault_tasks():
    aip = AlienvaultIP("AlienvaultIP")
    aip.analytics = Analytics()
    run =  aip.update()
    if run is None:
        raise alienvault_tasks.retry(countdown=60)
    return run

@celery.task
def dshield_as16276_tasks():
    ds_as = DShield16276("DShield16276")
    ds_as.analytics = Analytics()
    run =  ds_as.update()
    if run is None:
        raise dshield_as16276_tasks.retry(countdown=60)
    return run

@celery.task
def dshield_as3215_tasks():
    ds_as = DShield3215("DShield3215")
    ds_as.analytics = Analytics()
    run =  ds_as.update()
    if run is None:
        raise dshield_as3215_tasks.retry(countdown=60)
    return run

@celery.task
def malcodebinaries_tasks():
    mb = MalcodeBinaries("MalcodeBinaries")
    mb.analytics = Analytics()
    run =  mb.update()
    if run is None:
        raise malcodebinaries_tasks.retry(countdown=60)
    return run

@celery.task
def malwarepatrolvx_tasks():
    mp = MalwarePatrolVX("MalwarePatrolVX")
    mp.analytics = Analytics()
    run =  mp.update()
    if run is None:
        raise malwarepatrolvx_tasks.retry(countdown=60)
    return run

@celery.task
def openblip_tasks():
    oblip = OpenblIP("OpenblIP")
    oblip.analytics = Analytics()
    run =  oblip.update()
    if run is None:
        raise openblip_tasks.retry(countdown=60)
    return run

@celery.task
def palevotracker_tasks():
    pt = PalevoTracker("PalevoTracker")
    pt.analytics = Analytics()
    run =  pt.update()
    if run is None:
        raise palevotracker_tasks.retry(countdown=60)
    return run

@celery.task
def siriurzvx_tasks():
    su = SiriUrzVX("SiriUrzVX")
    su.analytics = Analytics()
    run =  su.update()
    if run is None:
        raise siriurzvx_tasks.retry(countdown=60)
    return run

@celery.task
def suspiciousdomains_tasks():
    sd = SuspiciousDomains("SuspiciousDomains")
    sd.analytics = Analytics()
    run =  sd.update()
    if run is None:
        raise suspiciousdomains_tasks.retry(countdown=60)
    return run

@celery.task
def torexitnodes_tasks():
    ten = TorExitNodes("TorExitNodes")
    ten.analytics = Analytics()
    run =  ten.update()
    if run is None:
        raise torexitnodes_tasks.retry(countdown=60)
    return run


