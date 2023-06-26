from __future__ import unicode_literals

from mongoengine import IntField, DictField
import iptools

from core.observables import Observable
from core.helpers import refang


class Ip(Observable):
    geoip = DictField()
    regex = r"(?P<search>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.,](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[?[.,]\]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\[?[.,]\]?(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b)\[?\.\]?){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|(([0-9A-Fa-f]{1,4}:){0,5}:((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b)\[?\.\]){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|(::([0-9A-Fa-f]{1,4}:){0,5}((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b)\[?\.\]){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|([0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)))"
    version = IntField()

    exclude_fields = Observable.exclude_fields + ["version"]

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS + [
        ("version", "IP version"),
        ("geoip__country", "Country"),
        ("geoip__city", "City"),
    ]

    ignore = iptools.IpRangeList(
        iptools.ipv4.BENCHMARK_TESTS,
        iptools.ipv4.BROADCAST,
        iptools.ipv4.DUAL_STACK_LITE,
        iptools.ipv4.IETF_PROTOCOL_RESERVED,
        iptools.ipv4.LINK_LOCAL,
        iptools.ipv4.LOOPBACK,
        iptools.ipv4.LOCALHOST,
        iptools.ipv4.MULTICAST,
        iptools.ipv4.MULTICAST_INTERNETWORK,
        iptools.ipv4.MULTICAST_LOCAL,
        iptools.ipv4.PRIVATE_NETWORK_10,
        iptools.ipv4.PRIVATE_NETWORK_172_16,
        iptools.ipv4.PRIVATE_NETWORK_192_168,
    )

    @classmethod
    def is_valid(cls, match):
        value = refang(match.group("search"))
        return iptools.ipv4.validate_ip(value) or iptools.ipv6.validate_ip(value)

    def normalize(self):
        self.value = refang(self.value)
        if iptools.ipv4.validate_ip(self.value):
            self.value = iptools.ipv4.hex2ip(iptools.ipv4.ip2hex(self.value))
            self.version = 4
        elif iptools.ipv6.validate_ip(self.value):
            self.value = iptools.ipv6.long2ip(iptools.ipv6.ip2long(self.value))
            self.version = 6

    def info(self):
        info = super(Ip, self).info()
        info["version"] = self.version
        info["geoip"] = self.geoip
        return info
