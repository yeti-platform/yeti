from __future__ import unicode_literals

import os
import sys
import pkgutil
import logging
import importlib
import inspect

from mongoengine import *
from celery.beat import Scheduler as BaseScheduler
from celery.beat import ScheduleEntry as BaseScheduleEntry

from core.config.celeryctl import celery_app
from core.config.mongoengine_extras import TimeDeltaField
from core.database import YetiDocument


class ScheduleEntry(YetiDocument):
    """Base class for Scheduling Entries. Everything that should be scheduled
       must inherit from this"""

    name = StringField(required=True, unique=True)
    enabled = BooleanField(default=True)
    description = StringField(required=True)
    frequency = TimeDeltaField(required=True)
    status = StringField()
    last_run = DateTimeField()
    lock = BooleanField(default=False)

    # This should be defined in subclasses, to define the name of the celery task
    SCHEDULED_TASK = None

    # This should be defined in subclasses, to set the field values
    default_values = None

    meta = {"allow_inheritance": True}

    def update_status(self, status):
        self.status = status
        self.save()

    @classmethod
    def unlock_all(klass):
        print klass.objects(lock=True).modify(lock=False)


class OneShotEntry(YetiDocument):
    name = StringField(required=True, unique=True)
    enabled = BooleanField(default=True)
    description = StringField(required=True)

    # This should be defined in subclasses, to set the field values
    default_values = None

    meta = {"allow_inheritance": True}


class Scheduler(BaseScheduler):

    SUBDIRS = ['feeds', 'analytics', 'exports']

    def __init__(self, *args, **kwargs):
        self._schedule = {}
        self.loaded_entries = {}
        logging.debug("Scheduler started")
        self.app = celery_app
        self.load_entries(ScheduleEntry, self.SUBDIRS)
        self.load_entries(OneShotEntry, self.SUBDIRS)

        if kwargs:
            super(Scheduler, self).__init__(*args, **kwargs)

    @property
    def schedule(self):
        return self._schedule

    @staticmethod
    def get_entries():
        entries = {}
        base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'plugins')
        sys.path.append(base_dir)

        for subdir in Scheduler.SUBDIRS:
            modules_dir = os.path.join(base_dir, subdir)
            for loader, name, ispkg in pkgutil.walk_packages([modules_dir], prefix='{}.'.format(subdir)):
                if not ispkg:
                    module = importlib.import_module(name)
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, (ScheduleEntry, OneShotEntry)) and obj.default_values is not None:
                            entries[obj.default_values['name']] = obj
                            if obj.default_values['name'] == 'dridex_paths':
                                print obj, name, base_dir, subdir
        return entries

    def load_entries(self, cls, subdirs):
        base_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'plugins')
        sys.path.append(base_dir)

        for sched in ScheduleEntry.objects.all():
            if sched.enabled:
                self.loaded_entries[sched.name] = sched

        for subdir in subdirs:
            modules_dir = os.path.join(base_dir, subdir)
            for loader, name, ispkg in pkgutil.walk_packages([modules_dir], prefix='{}.'.format(subdir)):
                if not ispkg:
                    module = importlib.import_module(name)
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, cls) and obj.default_values is not None:
                            try:
                                entry = obj.objects.get(name=obj.default_values['name'])
                            except DoesNotExist:
                                entry = obj(**obj.default_values)
                                entry.save()

                            self.loaded_entries[entry.name] = entry

    def setup_schedule(self):
        logging.debug("Setting up scheduler")
        for entry_name, entry in self.loaded_entries.iteritems():
            if isinstance(entry, ScheduleEntry):
                self._schedule[entry_name] = BaseScheduleEntry(name=entry_name,
                                                             app=self.app,
                                                             task=entry.SCHEDULED_TASK,
                                                             schedule=entry.frequency,
                                                             args=(str(entry.id), ))
