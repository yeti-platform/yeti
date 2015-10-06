from datetime import timedelta
import re
import logging

from core.analytics import Analytics
from core.datatypes import Link, Element

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
                Link.connect(src=url, dst=h)
            except ValueError:
                logging.error("An error occurred when trying to add {} to the database".format(host))
