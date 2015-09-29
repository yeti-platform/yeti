import logging
import os
import pkgutil
import importlib
import inspect
import csv
import sys
import datetime
from StringIO import StringIO

import requests
from core.config.celeryctl import celery_app
from celery.beat import Scheduler, ScheduleEntry
from lxml import etree
from mongoengine import *
from core.db.mongoengine_extras import TimedeltaField

@celery_app.task
def update_feed(feed_name):
    print "Running {}".format(feed_name)
    f = Feed.objects.get(name=feed_name)
    f.update()
    f.last_run = datetime.datetime.now()
    f.save()
    
class FeedEngine(Scheduler):
    """Feed manager class. Starts, stops, monitors feeds"""

    def __init__(self, *args, **kwargs):
        self._schedule = {}
        self.loaded_modules = {}
        logging.info("FeedEngine started")
        self.app = celery_app
        self.load_feeds()

        if kwargs:
            super(FeedEngine, self).__init__(*args, **kwargs)

    @property
    def schedule(self):
        return self._schedule

    def load_feeds(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        modules_dir = os.path.join(base_dir, 'feeds')
        sys.path.append(base_dir)
        for loader, name, ispkg in pkgutil.walk_packages([modules_dir], prefix='feeds.'):
            if not ispkg:
                module = importlib.import_module(name)
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, Feed) and obj is not Feed:
                        # logging.info("Loading feed {}".format(obj.name))
                        try:
                            feed = Feed.objects.get(name=obj.settings['name'])
                            print "Feed found in DB", feed
                        except DoesNotExist as e:
                            # print "Feed not found"
                            feed = obj(name=obj.settings['name'], source=obj.settings['source'], enabled=True, frequency=obj.settings['frequency']).save()
                            feed.save()
                        # logging.info("Loaded feed {}".format(feed.name))
                        # print feed, feed.name, obj.frequency, feed.frequency
                        self.loaded_modules[feed.name] = feed

    def setup_schedule(self):
        logging.info("Setting scheduler")
        for module in self.loaded_modules:
            self._schedule[module] = ScheduleEntry(name=module, app=self.app,
                                                   task= 'core.feed.update_feed',
                                                   schedule=self.loaded_modules[module].frequency,
                                                   args= (module, ))

class Feed(Document):
    """Base class for Feeds. All feeds must inherit from this"""

    name = StringField(required=True, unique=True)
    source = StringField(required=True)
    enabled = BooleanField()
    frequency = TimedeltaField(required=True)
    status = StringField()
    last_run = DateTimeField()

    meta = {"allow_inheritance": True}

    def update(self):
        """
        The update() function has to be implemented in each of your feeds.
        Its role is to:
         - Fetch data from wherever it needs to
         - Translate this data into elements understood by Malcom (as defined in malcom.datatypes.element)
         - Save these newly created elements to the database using the self.model attribute
        """
        raise NotImplementedError(
            "update: This method must be implemented in your feed class")

    def analyze(self):
        raise NotImplementedError(
            "analyze: This method must be implemented in your feed class")

    # Helper functions

    def update_xml(self, main_node, children, headers={}, auth=None):
        assert self.source is not None

        if auth:
            r = requests.get(self.source, headers=headers, auth=auth)
        else:
            r = requests.get(self.source, headers=headers)

        self.status = "Update OK"

        return self.parse_xml(r.content, main_node, children)

    def parse_xml(self, data, main_node, children):

        tree = etree.parse(StringIO(data))

        for item in tree.findall("//{}".format(main_node)):
            context = {}
            for field in children:
                context[field] = item.findtext(field)

            context['source'] = self.name

            yield context

    def update_lines(self, headers={}, auth=None):
        assert self.source is not None

        if auth:
            r = requests.get(self.source, headers=headers, auth=auth)
        else:
            r = requests.get(self.source, headers=headers)

        feed = r.text.split('\n')

        self.status = "Update OK"

        for line in feed:
            yield line

    def update_csv(self, delimiter=';', quotechar="'", headers={}, auth=None):
        assert self.source is not None

        if auth:
            r = requests.get(self.source, headers=headers, auth=auth)
        else:
            r = requests.get(self.source, headers=headers)

        feed = r.text.split('\n')
        reader = csv.reader(feed, delimiter=delimiter, quotechar=quotechar)

        self.status = "Update OK"

        for line in reader:
            yield line

    def update_json(self, headers={}, auth=None):
        if auth:
            r = requests.get(self.source, headers=headers, auth=auth)
        else:
            r = requests.get(self.source, headers=headers)

        self.status = "Update OK"

        return r.json()
