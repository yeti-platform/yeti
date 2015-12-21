import csv
import requests
from datetime import datetime
import logging
from StringIO import StringIO

from lxml import etree
from mongoengine import StringField

from core.config.celeryctl import celery_app
from core.scheduling import ScheduleEntry


@celery_app.task
def update_feed(feed_name):

    f = Feed.objects.get(name=feed_name)
    try:
        if f.enabled:
            logging.info("Running {}".format(feed_name))
            f.update_status("Updating...")
            f.update()
            f.update_status("OK")
        else:
            logging.error("Feed {} has been disabled".format(feed_name))
    except Exception as e:
        msg = "ERROR updating feed: {}".format(e)
        logging.error(msg)
        f.update_status(msg)

    f.last_run = datetime.now()
    f.save()


class Feed(ScheduleEntry):
    """Base class for Feeds. All feeds must inherit from this"""

    SCHEDULED_TASK = "core.feed.update_feed"

    source = StringField(required=True)

    def update(self):
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

        for line in reader:
            yield line

    def update_json(self, headers={}, auth=None):
        if auth:
            r = requests.get(self.source, headers=headers, auth=auth)
        else:
            r = requests.get(self.source, headers=headers)

        return r.json()

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ["name", "enabled", "description", "source", "status", "last_run"]}
        i['frequency'] = str(self.frequency)
        i['id'] = str(self.id)
        return i
