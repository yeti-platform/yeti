from datetime import timedelta
import re
import logging

from core.analytics import ScheduledAnalytics
from core.observables import Link, Observable


class ProcessUrl(ScheduledAnalytics):

    settings = {
        "frequency": timedelta(minutes=5),
        "name": "ProcessUrl",
        "description": "Extracts domains from URLs",
    }

    ACTS_ON = 'Url'
    EXPIRATION = None  # only run this once

    @staticmethod
    def each(url):
        host = re.search("://(?P<host>[^/:]+)[/:]", url.value)
        if host:
            host = host.group('host')
            try:
                logging.info("Extracted {} from {}".format(host, url))
                h = Observable.guess_type(host).get_or_create(value=host)
                Link.connect(src=url, dst=h)
            except ValidationError:
                logging.error("An error occurred when trying to add {} to the database".format(host))
