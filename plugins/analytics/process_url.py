from __future__ import unicode_literals
from datetime import timedelta
import re
import logging

from core.analytics import ScheduledAnalytics
from core.observables import Observable
from core.errors import ObservableValidationError


class ProcessUrl(ScheduledAnalytics):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "ProcessUrl",
        "description": "Extracts domains from URLs",
    }

    ACTS_ON = 'Url'
    EXPIRATION = None  # only run this once

    @staticmethod
    def analyze_string(url_string):
        return [ProcessUrl.extract_hostname(url_string)]

    @staticmethod
    def extract_hostname(url_string):
        host = re.search("://(?P<host>[^/:]+)[/:]?", url_string)
        if host:
            host = host.group('host')
            logging.info("Extracted {} from {}".format(host, url_string))
        return host

    @staticmethod
    def each(url):
        try:
            host = ProcessUrl.analyze_string(url.value)[0]
            h = Observable.guess_type(host).get_or_create(value=host)
            h.add_source("analytics")
            url.active_link_to(h, "hostname", "ProcessUrl", clean_old=False)
        except ObservableValidationError:
            logging.error("An error occurred when trying to add {} to the database".format(host))
