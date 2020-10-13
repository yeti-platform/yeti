from __future__ import unicode_literals

import json
import logging
import os
import tempfile
import xml.etree.ElementTree as ET
from base64 import b64decode
from datetime import datetime
from io import StringIO, BytesIO
from zipfile import ZipFile

import pandas as pd
import pytz
import requests
from dateutil import parser
from mongoengine import DoesNotExist, StringField

from core.config.celeryctl import celery_app
from core.config.config import yeti_config
from core.errors import GenericYetiError, GenericYetiInfo
from core.scheduling import ScheduleEntry

utc = pytz.UTC


@celery_app.task
def update_feed(feed_id):
    try:
        f = Feed.objects.get(
            id=feed_id, lock=None
        )  # check if we have implemented locking mechanisms
    except DoesNotExist:
        try:
            Feed.objects.get(id=feed_id, lock=False).modify(
                lock=True
            )  # get object and change lock
            f = Feed.objects.get(id=feed_id)
        except DoesNotExist:
            # no unlocked Feed was found, notify and return...
            logging.debug(
                "Feed {} is already running...".format(
                    Feed.objects.get(id=feed_id).name
                )
            )
            return False

    try:
        if f.enabled:
            logging.debug("Running {} (ID: {})".format(f.name, f.id))
            f.update_status("Updating...")
            f.update()
            f.update_status("OK")
        else:
            logging.debug("Feed {} has been disabled".format(f.name))
    except GenericYetiInfo as e:
        msg = "INFO updating feed: {}".format(e)
        logging.info(msg)
        f.update_status(msg)
        f.modify(lock=False)
        return True

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

    def _temp_save_feed_data(self, content):
        """
        This function will save data for the feed which doesn't provide date
        to be able compare between latest fetched data and just fetched data
        to not process the same data over and over

        content: the fetched data to be stored
        """

        tmp_folder = tempfile.gettempdir()
        feed_file = os.path.join(tmp_folder, self.name)
        with open(feed_file, "w") as f:
            try:
                f.write(content)
            except UnicodeEncodeError as e:
                logging.error(e)

    def _temp_load_feed_data(self):
        """
        This function will load stored data from previous fetch
        """

        content = set()
        tmp_folder = tempfile.gettempdir()
        feed_file = os.path.join(tmp_folder, self.name)

        if os.path.exists(feed_file):
            with open(feed_file, "r") as f:
                # requires to remove newline for correct comparison
                content = set([line.strip() for line in f.readlines()])

        return content

    def _temp_feed_data_compare(self, content):

        """
        First load data from last fetch to compare them with current data
        This is useful for feeds without Last-modified header
        and where no date to check
        """

        old_data_set = self._temp_load_feed_data()
        new_data_set = set(content.splitlines())

        new_data_set = new_data_set.difference(old_data_set)

        self._temp_save_feed_data(content)

        return list(new_data_set)

    def update(self):
        """Function responsible for retreiving the data for a feed and calling
        the ``analyze`` function on its data, typically one line at a time.

        Helper functions may be called to facilitate parsing of common data formats.

        Raises:
            NotImplementedError if no function has been implemented.
        """

        raise NotImplementedError(
            "update: This method must be implemented in your feed class"
        )

    def analyze(self, item):
        """Function responsible for processing the item passed on by
        the ``update`` function.

        Raises:
            NotImplementedError if no function has been implemented.
        """
        raise NotImplementedError(
            "analyze: This method must be implemented in your feed class"
        )

    # Helper functions
    def _choose(
        self,
        feed,
        delimiter=";",
        comment="#",
        filter_row=None,
        names=None,
        header=0,
        compare=False,
        date_parser=None,
    ):
        df = None
        if filter_row:
            if comment and names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    comment=comment,
                    names=names,
                    parse_dates=[filter_row],
                    date_parser=date_parser,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )

            elif header and not comment and not names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    header=header,
                    parse_dates=[filter_row],
                    date_parser=date_parser,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )
            elif header and comment and not names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    header=header,
                    comment=comment,
                    parse_dates=[filter_row],
                    date_parser=date_parser,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )

            elif not header and comment and not names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    comment=comment,
                    parse_dates=[filter_row],
                    date_parser=date_parser,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )
            elif not header and not comment and not names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    parse_dates=[filter_row],
                    date_parser=date_parser,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )
        else:

            if comment and names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    comment=comment,
                    names=names,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )
            elif not comment and names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    comment=comment,
                    names=names,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )
            elif header and not comment and not names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    header=header,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )
            elif header and comment and not names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    header=header,
                    comment=comment,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )

            elif not header and comment and not names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    comment=comment,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )
            elif not header and not comment and not names:
                df = pd.read_csv(
                    StringIO(feed),
                    delimiter=delimiter,
                    quotechar='"',
                    quoting=True,
                    skipinitialspace=True,
                )

        return df

    def _unzip_content(self, data):
        f = ZipFile(BytesIO(data))
        name = f.namelist()[0]
        unzip_data = f.read(name)
        return unzip_data

    def _make_request(
        self,
        method="get",
        headers={},
        auth=None,
        params={},
        data={},
        url=False,
        verify=True,
        sort=True,
    ):

        """Helper function. Performs an HTTP request on ``source`` and returns request object.

        Args:
            method:     Optional HTTP method to use GET/POST/etc lowercase
            headers:    Optional headers to be added to the HTTP request.
            auth:       Username / password tuple to be sent along with the HTTP request.
            params:     Optional param to be added to the HTTP GET request.
            data:       Optional param to be added to the HTTP POST request.
            url:        Optional url to be fetched instead of self.source
            verify:     optional verify to verify domain certificate

        Returns:
            requests object.
        """
        if auth:
            r = getattr(requests, method)(
                url or self.source,
                headers=headers,
                auth=auth,
                proxies=yeti_config.proxy,
                params=params,
                data=data,
                verify=verify,
                stream=True,
            )
        else:
            r = getattr(requests, method)(
                url or self.source,
                headers=headers,
                proxies=yeti_config.proxy,
                params=params,
                data=data,
                verify=verify,
                stream=True,
            )

        if r.status_code != 200:
            raise GenericYetiError(
                "{} returns code: {}".format(self.source, r.status_code)
            )
        if sort:
            if self.last_run is not None and r.headers.get("Last-Modified"):
                last_mod = parser.parse(r.headers["Last-Modified"])
                if self.last_run and self.last_run > last_mod.replace(tzinfo=None):
                    raise GenericYetiInfo(
                        "Last modified date: {} returns code: {}".format(
                            last_mod, r.status_code
                        )
                    )

        return r

    def update_xml(self, main_node, children, headers=None, auth=None, verify=True):
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
            verify: Force ssl verification.

        Returns:
            Yields Python ``dictionary`` objects. The dicitonary keys are the strings specified in the ``children`` array.
        """
        assert self.source is not None

        r = self._make_request(headers=headers, auth=auth, verify=verify)
        return self.parse_xml(r.content.decode(), main_node, children)

    def parse_xml(self, data, main_node, children):
        """Helper function used to parse XML. See :func:`core.feed.Feed.update_xml` for details"""

        tree = ET.fromstring(data)

        for item in tree.findall(".//{}".format(main_node)):
            context = {}
            for field in children:
                context[field] = item.findtext(field)

            context["source"] = self.name

            yield context

    def update_lines(self, headers=None, auth=None, verify=True):
        """Helper function. Performs an HTTP request on ``source`` and treats each
        line of the response separately.


        Args:
            headers:    Optional headers to be added to the HTTP request.
            auth:       Username / password tuple to be sent along with the HTTP request.
            verify: Force ssl verification.

        Returns:
            Yields string lines from the HTTP response.
        """
        assert self.source is not None

        r = self._make_request(headers=headers, auth=auth, verify=verify)
        feed = self._temp_feed_data_compare(
            r.content.decode("utf-8", "backslashreplace")
        )
        for line in feed:
            yield line

    def utf_8_encoder(self, unicode_csv_data):
        for line in unicode_csv_data:
            yield line.encode("utf-8")

    def update_csv(
        self,
        delimiter=";",
        headers=None,
        auth=None,
        verify=True,
        comment="#",
        filter_row=None,
        names=None,
        header=0,
        compare=False,
        date_parser=None,
        content_zip=False,
    ):
        """Helper function. Performs an HTTP request on ``source`` and treats
        the response as an CSV file, yielding a ``dict`` for each parsed line.

        Args:
            delimiter:  A string delimiting fields in the CSV. Default is ``;``.
            headers:    Optional headers to be added to the HTTP request.
            auth:       Username / password tuple to be sent along with the HTTP request.
            verify: Force ssl verification.
            comment: Comment char in csv data for panda.
            filter_row: name of columns to filter rows
            names: names of columns of the dataframe
            header: number of the if the name of columns is specified in csv data.
            compare: if the filtering must be made by the last run
            date_parser: function to parse the date
        Returns:
            return a dataframe pandas filtered by date of the last run
        """
        assert self.source is not None

        r = self._make_request(sort=False, headers=headers, auth=auth, verify=verify)
        content = r.content

        if content_zip:
            content = self._unzip_content(content)

        feed = content.decode()

        df = self._choose(
            feed,
            delimiter=delimiter,
            comment=comment,
            filter_row=filter_row,
            names=names,
            header=header,
            date_parser=date_parser,
        )

        df.drop_duplicates(inplace=True)
        df.fillna("", inplace=True)

        if self.last_run and filter_row:
            df = df[df[filter_row] > self.last_run]

        return df.iterrows()

    def update_json(
        self,
        method="get",
        data=None,
        headers=None,
        auth=None,
        params=None,
        verify=True,
        filter_row="",
        key=None,
    ):
        """Helper function. Performs an HTTP request on ``source`` and parses
        the response JSON, returning a Python ``dict`` object.

        Args:
            method:     Optional HTTP method to use GET/POST/etc lowercase
            headers:    Optional headers to be added to the HTTP request.
            data:       Dictionary containing POST data to send.
            auth:       Username / password tuple to be sent along with the HTTP request.
            params:     Optional param to be added to the HTTP request.
            verify:     Force SSL verification.
            filter_row: Name of columns to filter rows.
            key:        Key in JSON response to return data.
        Returns:
            Python ``dict`` object representing the response JSON.
        """

        r = self._make_request(
            method=method,
            headers=headers,
            auth=auth,
            params=params,
            data=data,
            verify=verify,
        )

        if key:
            content = r.json().get(key)
        else:
            content = r.json()
        if not content:
            return []

        if filter_row:
            df = pd.read_json(
                StringIO(json.dumps(content)),
                orient="values",
                convert_dates=[filter_row],
            )
        else:
            df = pd.read_json(StringIO(json.dumps(content)), orient="values")

        df.fillna("", inplace=True)

        if filter_row and self.last_run:
            df.sort_values(by=filter_row, inplace=True, ascending=False)
            df = df[df[filter_row] > self.last_run]

        return df.iterrows()

    def parse_commit(self, item, headers, verify=True):
        """
            Helper function used to parse github commit and extract content.
            See :func:`core.feed.Feed.update_github` for details

        Args:
            item:    All details about an github commit
            headers: Used for correct github auth or empty
        Returns:
            Yields all new content for the commit and filename of the original file
        """

        commit_info = self._make_request(
            url=item["url"], headers=headers, verify=verify
        )

        commit_info = commit_info.json()
        if commit_info and commit_info.get("files", []):
            for block in commit_info["files"]:
                if block["filename"] in self.blacklist:
                    continue

                content = False
                if "patch" in block:
                    # load only additions
                    content = "\n".join(
                        [
                            line[1:]
                            for line in block["patch"].split("\n")
                            if line.startswith("+")
                        ]
                    )

                elif "contents_url" in block:
                    data = self._make_request(
                        url=block["contents_url"], headers=headers, verify=verify
                    ).json()
                    if data.get("encoding") and data.get("content"):
                        content = b64decode(data["content"])
                        if data.get("name", ""):
                            block["filename"] = data["name"]

                yield content, block["filename"]

    def update_github(self, headers=None, auth=None, params=None, verify=True):
        """Helper function. Grabs data about latest commits iterates them.

        Args:
            headers:    Optional headers to be added to the HTTP request.
            auth:       Username / password tuple to be sent along with the HTTP request.
            params:     Optional param to be added to the HTTP request.

        Returns:
            Python ``dict`` object representing the response JSON.
            Example:
                https://api.github.com/repos/eset/malware-ioc/commits/2602f02a1b0ff6d4cfcefecf93f3b4320d8b4207
        """

        if hasattr(yeti_config, "github") and yeti_config.github.token:
            headers = {"Authorization": "token " + yeti_config.github.token}
        else:
            headers = {}

        since_last_run = utc.localize(datetime.utcnow() - self.frequency)
        r = self._make_request(headers=headers, auth=auth, verify=verify)
        if r.status_code == 200:
            for item in r.json():
                if parser.parse(item["commit"]["author"]["date"]) > since_last_run:
                    break
                try:
                    return self.parse_commit(item, headers)
                except GenericYetiError as e:
                    logging.error(e)
        return []

    def info(self):
        i = {
            k: v
            for k, v in self._data.items()
            if k in ["name", "enabled", "description", "source", "status", "last_run"]
        }
        i["frequency"] = str(self.frequency)
        i["id"] = str(self.id)
        return i
