from datetime import timedelta
import re
import logging

from core.analytics import Analytics
from core.db.datatypes import Hostname, Link, Element
from core.helpers import url_regex, tlds

class ProcessUrl(Analytics):

    settings = {
        "frequency": timedelta(minutes=10),
        "name": "ProcessUrl",
        "description": "Extracts domains from URLs",
    }

    ACTS_ON = 'Url'
    CUSTOM_FILTER = {}
    EXPIRATION = None  # only run this once

    @staticmethod
    def each(url):
        host = re.search("://(?P<host>[^/]+)/", url.value)
        if host:
            host = host.group('host')
            try:
                logging.info("Extracted {} from {}".format(host, url))
                h = Element.guess_type(host).get_or_create(value=host)
                l = Link.connect(src=url, dst=h)
            except ValueError as e:
                logging.error("An error occurred when trying to add {} to the database".format(host))
