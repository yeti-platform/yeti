from datetime import timedelta
import re
import logging

from core.analytics import ScheduledAnalytics
from core.observables import Observable
from core.database import Link
from core.errors import ObservableValidationError


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
            except ObservableValidationError:
                logging.error("An error occurred when trying to add {} to the database".format(host))
