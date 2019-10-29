from __future__ import unicode_literals

import re
from urllib.parse import urlparse

from url_normalize import url_normalize
from mongoengine import DictField

from core.common.utils import tldextract_parser
from core.observables import Observable
from core.observables.hostname import Hostname
from core.observables.ip import Ip
from core.errors import ObservableValidationError
from core.helpers import refang


class Url(Observable):

    parsed_url = DictField()
    regex = r"(?P<search>((?P<scheme>[\w]{2,9}):\/\/)?([\S]*\:[\S]*\@)?(?P<hostname>" + Hostname.main_regex + ")(\:[\d]{1,5})?(?P<path>(\/[\S]*)?(\?[\S]*)?(\#[\S]*)?))"
    search_regex = r"(?P<search>((?P<scheme>[\w]{2,9}):\/\/)?([\S]*\:[\S]*\@)?(?P<hostname>" + Hostname.main_regex + ")(\:[\d]{1,5})?(?P<path>((\/[\S]*)?(\?[\S]*)?(\#[\S]*)?)[\w/])?)"

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS + [
        ("parsed_url__netloc", "Host"),
        ("parsed_url__params", "Parameters"),
        ("parsed_url__path", "Path"),
        ("parsed_url__query", "Query"),
        ("parsed_url__scheme", "Scheme"),
        ("parsed_url__port", "Port"),
    ]

    @classmethod
    def is_valid(cls, match):
        return ((match.group('search').find('/') != -1) and (
            Hostname.check_type(match.group('hostname')) or
            Ip.check_type(match.group('hostname'))))

    def normalize(self):
        self.value = refang(self.value)


        if re.match(r"[^:]+://", self.value) is None:
            # if no schema is specified, assume http://
            self.value = u"http://{}".format(self.value)
        try:
            self.value = url_normalize(self.value).replace(' ', '%20')
        except Exception as e:
            raise ObservableValidationError(
                "Invalid URL: {}".format(self.value))

        try:
            p = tldextract_parser(self.value)
            self.value = self.value.replace(p.fqdn,
                                            p.fqdn.encode("idna").decode(), 1)
            self.parse()
        except UnicodeDecodeError:
            raise ObservableValidationError(
                "Invalid URL (UTF-8 decode error): {}".format(self.value))

    def parse(self):
        parsed = urlparse(self.value)

        self.parsed_url = {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc.split(":")[0],
            "port": parsed.port if parsed.port else "80",
            "path": parsed.path,
            "params": parsed.params,
            "query": parsed.query,
            "fragment": parsed.fragment
        }
