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
from core.datatypes.mongoengine_extras import TimeDeltaField

class ScheduleEntry(Document):
    """Base class for Scheduling Entries. Everything that should be scheduled
       must inherit from this"""

    name = StringField(required=True, unique=True)
    enabled = BooleanField()
    description = StringField(required=True)
    frequency = TimeDeltaField(required=True)
    status = StringField()
    last_run = DateTimeField()

    # This should be defined in subclasses, to define the name of the celery task
    SCHEDULED_TASK = None

    # This should be defined in subclasses, to set the field values
    settings = None

    meta = {"allow_inheritance": True}

class Scheduler(BaseScheduler):

    SUBDIRS = ['feeds', 'analytics']

    def __init__(self, *args, **kwargs):
        self._schedule = {}
        self._loaded_entries = {}
        logging.info("Scheduler started")
        self.app = celery_app
        self.load_entries()

        if kwargs:
            super(Scheduler, self).__init__(*args, **kwargs)

    @property
    def schedule(self):
        return self._schedule

    def load_entries(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.append(base_dir)

        for subdir in self.SUBDIRS:
            modules_dir = os.path.join(base_dir, subdir)
            for loader, name, ispkg in pkgutil.walk_packages([modules_dir], prefix='{}.'.format(subdir)):
                if not ispkg:
                    module = importlib.import_module(name)
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if issubclass(obj, ScheduleEntry) and obj.settings is not None:
                            try:
                                entry = obj.objects.get(name=obj.settings['name'])
                            except DoesNotExist:
                                entry = obj(**obj.settings)
                                entry.save()

                            self._loaded_entries[entry.name] = entry

    def setup_schedule(self):
        logging.info("Setting up scheduler")
        for name, entry in self._loaded_entries.iteritems():
            self._schedule[name] = BaseScheduleEntry(name=name, app=self.app,
                                                     task=entry.SCHEDULED_TASK,
                                                     schedule=entry.frequency,
                                                     args=(name, ))
