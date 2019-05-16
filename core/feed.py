from __future__ import unicode_literals

import csv
import logging
from StringIO import StringIO
from datetime import datetime

import requests
from lxml import etree
from mongoengine import DoesNotExist
from mongoengine import StringField

from core.errors import GenericYetiError
from core.config.celeryctl import celery_app
from core.config.config import yeti_config
from core.scheduling import ScheduleEntry


@celery_app.task
def update_feed(feed_id):

    try:
        f = Feed.objects.get(
            id=feed_id,
            lock=None)  # check if we have implemented locking mechanisms
    except DoesNotExist:
        try:
            Feed.objects.get(
                id=feed_id, lock=False).modify(
                    lock=True)  # get object and change lock
            f = Feed.objects.get(id=feed_id)
        except DoesNotExist:
            # no unlocked Feed was found, notify and return...
            logging.debug(
                "Feed {} is already running...".format(
                    Feed.objects.get(id=feed_id).name))
            return False

    try:
        if f.enabled:
            logging.debug("Running {} (ID: {})".format(f.name, f.id))
            f.update_status("Updating...")
            f.update()
            f.update_status("OK")
        else:
            logging.debug("Feed {} has been disabled".format(f.name))
    except Exception as e:
        import traceback
        logging.error(traceback.format_exc())
        msg = "ERROR updating feed: {}".format(e)
        logging.error(msg)
        f.update_status(msg)
        f.modify(lock=False)
        return False

    f.modify(lock=False, last_run=datetime.utcnow())
    return True


class Feed(ScheduleEntry):
    """Base class for Feeds. All feeds must inherit from this.

    Feeds describe the way Yeti automatically collects and processes data.

    Attributes:
        frequency:
            A ``timedelta`` variable defining the frequency at which a feed is to be ran. Example: ``timedelta(hours=1)``
        name:
            Required. The feed's name. Must be the same as the class name. Example: ``"ZeusTrackerConfigs"``
        source:
            f working with helpers. This designates URL on which to fetch the data. Example: ``"https://zeustracker.abuse.ch/monitor.php?urlfeed=configs"``
        description:
            Bref feed description. Example: ``"This feed shows the latest 50 ZeuS config URLs."``

    .. note::
        These attributes must be defined in every class inheriting from ``Feed`` as the key - value items of a ``default_values`` attribute. See :ref:`creating-feed` for more details

    """

    SCHEDULED_TASK = "core.feed.update_feed"

    source = StringField()

    def update(self):
        """Function responsible for retreiving the data for a feed and calling
        the ``analyze`` function on its data, typically one line at a time.

        Helper functions may be called to facilitate parsing of common data formats.

        Raises:
            NotImplementedError if no function has been implemented.
        """

        raise NotImplementedError(
            "update: This method must be implemented in your feed class")

    def analyze(self, item):
        """Function responsible for processing the item passed on by
        the ``update`` function.

        Raises:
            NotImplementedError if no function has been implemented.
        """
        raise NotImplementedError(
            "analyze: This method must be implemented in your feed class")

    # Helper functions

    def _make_request(self, headers={}, auth=None, params={}):

        """Helper function. Performs an HTTP request on ``source`` and returns request object.

        Args:
            headers:    Optional headers to be added to the HTTP request.
            auth:       Username / password tuple to be sent along with the HTTP request.
            params:     Optional param to be added to the HTTP request.

        Returns:
            requests object.
        """

        if auth:
            r = requests.get(
                self.source, 
                headers=headers,
                auth=auth,
                proxies=yeti_config.proxy,
                params=params)
        else:
            r = requests.get(
                self.source, headers=headers, proxies=yeti_config.proxy)

        if r.status_code != 200:
            raise GenericYetiError("{} returns code: {}".format(self.source, r.status_code))

        return r

    def update_xml(self, main_node, children, headers={}, auth=None):
        """Helper function. Performs an HTTP request on ``source`` and treats
        the response as an XML object, yielding a ``dict`` for each parsed
        element.

        The XML must have a ``main_node``, and an array of ``children``. For example::

            <main_node>
                <child1></child1>
                <child1></child2>
                <child1></child3>
            </main_node>

        Args:
            main_node:  A string defining the parent node that delimitates a ``dict`` to be yielded.
            children:   An array of strings defining the children of the parent node.
                        These will be the keys of the ``dict``.
            headers:    Optional headers to be added to the HTTP request.
            auth:       Username / password tuple to be sent along with the HTTP request.

        Returns:
            Yields Python ``dictionary`` objects. The dicitonary keys are the strings specified in the ``children`` array.
        """
        assert self.source is not None

        r = self._make_request(headers, auth)
        return self.parse_xml(r.content, main_node, children)

    def parse_xml(self, data, main_node, children):
        """Helper function used to parse XML. See :func:`core.feed.Feed.update_xml` for details"""

        tree = etree.parse(StringIO(data))

        for item in tree.findall("//{}".format(main_node)):
            context = {}
            for field in children:
                context[field] = item.findtext(field)

            context['source'] = self.name

            yield context

    def update_lines(self, headers={}, auth=None):
        """Helper function. Performs an HTTP request on ``source`` and treats each
        line of the response separately.


        Args:
            headers:    Optional headers to be added to the HTTP request.
            auth:       Username / password tuple to be sent along with the HTTP request.

        Returns:
            Yields string lines from the HTTP response.
        """
        assert self.source is not None

        r = self._make_request(headers, auth)
        feed = r.text.split('\n')

        for line in feed:
            yield line

    def utf_8_encoder(self, unicode_csv_data):
        for line in unicode_csv_data:
            yield line.encode('utf-8')

    def update_csv(self, delimiter=';', quotechar="'", headers={}, auth=None):
        """Helper function. Performs an HTTP request on ``source`` and treats
        the response as an CSV file, yielding a ``dict`` for each parsed line.

        Args:
            delimiter:  A string delimiting fields in the CSV. Default is ``;``.
            quotechar:  A string used to know when to ignore delimiters / carriage returns. Default is ``'``.
            headers:    Optional headers to be added to the HTTP request.
            auth:       Username / password tuple to be sent along with the HTTP request.

        Returns:
            Yields arrays of UTF-8 strings that correspond to each comma separated field
        """
        assert self.source is not None

        r = self._make_request(headers, auth)
        feed = r.text.split('\n')
        reader = csv.reader(
            self.utf_8_encoder(feed), delimiter=delimiter, quotechar=quotechar)

        for line in reader:
            yield line

    def update_json(self, headers={}, auth=None, params={}):
        """Helper function. Performs an HTTP request on ``source`` and parses
        the response JSON, returning a Python ``dict`` object.

        Args:
            headers:    Optional headers to be added to the HTTP request.
            auth:       Username / password tuple to be sent along with the HTTP request.
            params:     Optional param to be added to the HTTP request.

        Returns:
            Python ``dict`` object representing the response JSON.
        """

        r = self._make_request(headers, auth, params)
        return r.json()

    def info(self):
        i = {
            k: v
            for k, v in self._data.items()
            if k in
            ["name", "enabled", "description", "source", "status", "last_run"]
        }
        i['frequency'] = str(self.frequency)
        i['id'] = str(self.id)
        return i
