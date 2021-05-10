from __future__ import unicode_literals

import logging

from celery.beat import ScheduleEntry as BaseScheduleEntry
from celery.beat import Scheduler as BaseScheduler
from mongoengine import StringField, BooleanField, DateTimeField, connect

from core.config.celeryctl import celery_app
from core.config.config import yeti_config
from core.config.mongoengine_extras import TimeDeltaField
from core.database import YetiDocument
import ast


class ScheduleEntry(YetiDocument):
    """Base class for Scheduling Entries. Everything that should be scheduled
    must inherit from this"""

    name = StringField(required=True, unique=True)
    enabled = BooleanField(default=True)
    description = StringField()
    frequency = TimeDeltaField()
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
        print(klass.objects(lock=True).modify(lock=False))


class OneShotEntry(YetiDocument):
    name = StringField(required=True, unique=True)
    enabled = BooleanField(default=True)
    description = StringField()

    # This should be defined in subclasses, to set the field values
    default_values = None

    meta = {"allow_inheritance": True}


class Scheduler(BaseScheduler):
    def __init__(self, *args, **kwargs):
        self._schedule = {}
        logging.debug("Scheduler started")
        self.app = celery_app
        self.load_entries()

        if kwargs:
            super(Scheduler, self).__init__(*args, **kwargs)

    @property
    def schedule(self):
        return self._schedule

    def load_entries(self):
        connect(
            yeti_config.mongodb.database,
            host=yeti_config.mongodb.host,
            port=yeti_config.mongodb.port,
            username=yeti_config.mongodb.username,
            password=yeti_config.mongodb.password,
            tls=ast.literal_eval(yeti_config.mongodb.tls),
            connect=False,
        )
        from core.yeti_plugins import get_plugins

        self.loaded_entries = get_plugins()

    def setup_schedule(self):
        logging.debug("Setting up scheduler")
        for entry_name, entry in self.loaded_entries.items():
            if isinstance(entry, ScheduleEntry):
                self._schedule[entry_name] = BaseScheduleEntry(
                    name=entry_name,
                    app=self.app,
                    task=entry.SCHEDULED_TASK,
                    schedule=entry.frequency,
                    args=(str(entry.id),),
                )
