from mongoengine import *
import iptools

from core.observables import Observable

class Ip(Observable):

    version = IntField()

    IPV4_IGNORE_RANGE = iptools.IpRangeList(iptools.ipv4.BENCHMARK_TESTS,
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

    def clean(self):
        """Performs some normalization on IP addresses entered"""
        ip = self.value
        if iptools.ipv4.validate_ip(ip):  # is IPv4
            # if ip in self.IPV4_IGNORE_RANGE:
                # raise ValidationError("{} is in the ignore range".format(ip))
            self.value = iptools.ipv4.hex2ip(iptools.ipv4.ip2hex(ip))  # normalize ip
            self.version = 4
        elif iptools.ipv6.validate_ip(ip):  # is IPv6
            self.value = iptools.ipv6.long2ip(iptools.ipv6.ip2long(ip))  # normalize ip
            self.version = 6
        else:
            raise ValidationError("{} is not a valid IP address".format(ip))
