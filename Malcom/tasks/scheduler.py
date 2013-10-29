__author__ = 'pyt'

from Malcom.tasks.zeus import (zeustrackerbinaries_tasks,
                               zeustrackerconfigs_tasks,
                               zeustrackergameoverdomains_tasks,
                               zeustrackerdropzones_tasks
                               )
from Malcom.tasks.spyeye import (spyeyebinaries_tasks,
                                 spyeyecnc_tasks,
                                 spyeyeconfigs_tasks,
                                 spyeyedropzones_tasks
                                 )
from Malcom.tasks.mdl import (mdlhosts_tasks,
                              mdliplist_tasks,
                              mdltracker_tasks
                              )
from Malcom.tasks.other import (alienvault_tasks,
                                dshield_as16276_tasks,
                                dshield_as3215_tasks,
                                malcodebinaries_tasks,
                                malwarepatrolvx_tasks,
                                openblip_tasks,
                                palevotracker_tasks,
                                siriurzvx_tasks,
                                suspiciousdomains_tasks,
                                torexitnodes_tasks
                                )
from Malcom.celeryctl import celery
# from celery.contrib.methods import task_method
from celery import group

# class Scheduler(object):
#     def run(self):
#         self.worker.delay()
#
#     def init(self):
#         self.init = "init"

@celery.task()
def worker():
    res_ztbt = zeustrackerbinaries_tasks.s()
    res_ztct = zeustrackerconfigs_tasks.s()
    res_ztgodt = zeustrackergameoverdomains_tasks.s()
    res_ztdzt = zeustrackerdropzones_tasks.s()
    res_seb = spyeyebinaries_tasks.s()
    res_secnc = spyeyecnc_tasks.s()
    res_sec = spyeyeconfigs_tasks.s()
    res_sedz = spyeyedropzones_tasks.s()
    res_mdlhosts = mdlhosts_tasks.s()
    res_mdlil = mdliplist_tasks.s()
    res_mdlt = mdltracker_tasks.s()
    res_av = alienvault_tasks.s()
    res_d_as16276 = dshield_as16276_tasks.s()
    res_d_as3215 = dshield_as3215_tasks.s()
    res_mb = malcodebinaries_tasks.s()
    res_mpvx = malwarepatrolvx_tasks.s()
    res_oip = openblip_tasks.s()
    res_pt = palevotracker_tasks.s()
    res_su = siriurzvx_tasks.s()
    res_sd = suspiciousdomains_tasks.s()
    res_ten = torexitnodes_tasks.s()


    g_res = group(
        res_ztbt, res_ztct, res_ztgodt, res_ztdzt,
        res_seb, res_sec, res_secnc, res_sedz,
        res_mdlhosts, res_mdlil, res_mdlt,
        res_av, res_d_as16276, res_d_as3215,
        res_mb, res_mpvx, res_oip, res_pt,
        res_su, res_sd, res_ten
    )
    g_res.apply_async()
