import os
import time
import threading
import csv
import imp

from StringIO import StringIO

from datetime import timedelta, datetime

from multiprocessing import Process
from lxml import etree
import requests

from Malcom.auxiliary.toolbox import debug_output
from Malcom.model.model import Model
from Malcom.feeds.core.messenger import FeedsMessenger


class Feed(object):
    """This is a feed base class. All other feeds must inherit from this class"""

    def __init__(self, run_every="24h"):
        self.name = self.__class__.__name__

        # parse timedelta
        num = int(run_every[:-1])
        if run_every.endswith('s'):
            self.run_every = timedelta(seconds=num)
        if run_every.endswith('m'):
            self.run_every = timedelta(minutes=num)
        if run_every.endswith('h'):
            self.run_every = timedelta(hours=num)
        if run_every.endswith('d'):
            self.run_every = timedelta(days=num)

        self.last_run = None
        self.next_run = datetime.utcnow()
        self.running = False
        self.elements_fetched = 0
        self.status = "OK"
        self.enabled = True
        self.model = None
        self.testing = False
        self.tags = ['public']

    def get_dict(self):
        return {'name': self.name,
                'last_run': self.last_run,
                'next_run': self.next_run,
                'running': self.running,
                'elements_fetched': self.elements_fetched,
                'status': self.status,
                'enabled': self.enabled,
                'tags': self.tags,
                }

    def update_xml(self, main_node, children, headers={}, auth=None):
        assert self.source is not None

        if auth:
            r = requests.get(self.source, headers=headers, auth=auth)
        else:
            r = requests.get(self.source, headers=headers)

        self.status = "OK"

        return self.parse_xml(r.content, main_node, children)

    def parse_xml(self, data, main_node, children):

        tree = etree.parse(StringIO(data))

        for item in tree.findall("//{}".format(main_node)):
            evil = {}
            for field in children:
                evil[field] = item.findtext(field)

            evil['source'] = self.name

            yield evil

    def update_lines(self, headers={}, auth=None):
        assert self.source is not None
        # request = urllib2.Request(self.source, headers=headers)
        # feed = urllib2.urlopen(request).readlines()

        if auth:
            r = requests.get(self.source, headers=headers, auth=auth)
        else:
            r = requests.get(self.source, headers=headers)

        feed = r.text.split('\n')

        self.status = "OK"

        for line in feed:
            yield line

    def update_csv(self, delimiter=';', quotechar="'", headers={}, auth=None):
        assert self.source is not None
        # request = urllib2.Request(self.source, headers=headers)
        # feed = urllib2.urlopen(request).readlines()
        if auth:
            r = requests.get(self.source, headers=headers, auth=auth)
        else:
            r = requests.get(self.source, headers=headers)

        feed = r.text.split('\n')
        reader = csv.reader(feed, delimiter=delimiter, quotechar=quotechar)

        self.status = "OK"

        for line in reader:
            yield line

    def update_json(self, headers={}, auth=None):
        if auth:
            r = requests.get(self.source, headers=headers, auth=auth)
        else:
            r = requests.get(self.source, headers=headers)

        return r.json()

    def update(self):
        """
        The update() function has to be implemented in each of your feeds.
        Its role is to:
         - Fetch data from wherever it needs to
         - Translate this data into elements understood by Malcom (as defined in malcom.datatypes.element)
         - Save these newly created elements to the database using the self.model attribute
        """
        raise NotImplementedError("update: This method must be implemented in your feed class")

    def analyze(self):
        raise NotImplementedError("analyze: This method must be implemented in your feed class")

    def commit_to_db(self, element, testing=False):
        if self.testing:
            self.elements_fetched += 1
            return

        # add an 'evil' tag if it was not specified in the feed
        if 'evil' not in element['tags']:
            element['tags'] += ['evil']

        element, new = self.model.save(element, with_status=True)
        if new:
            self.elements_fetched += 1

        return element

    def run(self):
        self.running = True
        self.last_run = datetime.utcnow()
        self.next_run = self.last_run + self.run_every
        self.elements_fetched = 0

        # REDIS send messages to webserver
        # self.analytics.notify_progress("Feeding")
        try:
            t0 = datetime.now()
            self.update()
            t1 = datetime.now()
            debug_output("Feed {} added in {}".format(self.name, str(t1-t0)))
            # save time for record in db
            self.model.feed_last_run(self.name)
        except Exception, e:
            debug_output("Error adding feed {}: {}".format(self.name, e))
            self.status = "ERROR: {}".format(e)
            import traceback
            traceback.print_exc()

        self.running = False


class FeedEngine(Process):
    """Feed engine. This object will load and update feeds"""
    def __init__(self, configuration):
        Process.__init__(self)
        self.configuration = configuration
        self.model = Model(self.configuration)
        self.feeds = {}
        self.threads = {}
        self.global_thread = None
        # self.messenger = FeedsMessenger(self)

    def run_feed(self, feed_name):
        # Check if feed exists in list
        if not self.feeds.get(feed_name):
            return False

        # if feed is not already running
        if not (self.threads.get(feed_name) and self.threads[feed_name].is_alive()):
            self.threads[feed_name] = threading.Thread(None, self.feeds[feed_name].run, None)
            self.threads[feed_name].start()

        return True

    def run_all_feeds(self, block=False):
        debug_output("Running all feeds")
        for feed_name in [f for f in self.feeds if self.feeds[f].enabled]:
            debug_output('Starting thread for feed %s...' % feed_name)
            self.run_feed(feed_name)

        if block:
            for t in self.threads:
                if self.threads[t].is_alive():
                    self.threads[t].join()

    def stop_all_feeds(self):
        self.shutdown = True
        for t in self.threads:
            if self.threads[t].is_alive():
                self.threads[t]._Thread__stop()

    def run_scheduled_feeds(self):
        for f in self.feeds:
            if self.feeds[f].next_run < datetime.utcnow() and self.feeds[f].enabled:
                debug_output('Starting thread for feed %s...' % self.feeds[f].name)
                self.run_feed(self.feeds[f].name)

        for t in self.threads:
            if self.threads[t].is_alive():
                self.threads[t].join()

    def run(self):
        self.messenger = FeedsMessenger(self)
        self.shutdown = False
        while not self.shutdown:
            try:
                debug_output("FeedEngine heartbeat")
                if self.scheduler:
                    self.run_scheduled_feeds()
                time.sleep(self.period)  # run a new thread every period seconds
            except KeyboardInterrupt:
                self.shutdown = True

    def load_feeds(self, feed_directories):
        debug_output("Loading feeds in {}...".format(feed_directories))

        for d, subd, files in os.walk(feed_directories):
            if not d.endswith('core'):
                for f in files:
                    if f.endswith(".py") and f != "__init__.py":
                        try:
                            full_filename = os.path.join(d, f)
                            module = imp.load_source(f.split('.')[0], full_filename)

                            for name, obj in module.__dict__.items():
                                try:
                                    if issubclass(obj, Feed) and obj != Feed:
                                        feed = module.__dict__.get(name)()
                                        feed.model = self.model
                                        feed.engine = self
                                        feed.tags = list(set(feed.tags + [d]))
                                        self.feeds[name] = feed
                                        debug_output("Loaded feed {}".format(name))
                                        break
                                except TypeError:
                                    pass
                        except Exception, e:
                            debug_output("Something went wrong parsing {}".format(full_filename), type='error')
                            raise e

        self.load_feed_status()

    def load_feed_status(self):
        feed_status = self.model.get_feed_progress([f for f in self.feeds])
        for status in feed_status:
            name = status['name']
            self.feeds[name].last_run = status['last_run']
            self.feeds[name].next_run = status['last_run'] + self.feeds[name].run_every
