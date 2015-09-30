import csv
import requests
from lxml import etree
from StringIO import StringIO
from mongoengine import StringField
from core.config.celeryctl import celery_app
from core.scheduling import ScheduleEntry

@celery_app.task
def update_feed(feed_name):
    print "Running {}".format(feed_name)
    f = Feed.objects.get(name=feed_name)
    f.update()
    f.last_run = datetime.datetime.now()
    f.save()

class Feed(ScheduleEntry):
    """Base class for Feeds. All feeds must inherit from this"""

    SCHEDULED_TASK = "core.feed.update_feed"

    source = StringField(required=True)
    description = StringField(required=True)

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
