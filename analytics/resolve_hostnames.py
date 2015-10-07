from datetime import timedelta
import threading
import logging
from Queue import Queue

import dns
from dns.resolver import NoAnswer
from dns.rdtypes.ANY.NS import NS as NS_class
from dns.rdtypes.IN.A import A as A_class

from core.analytics import Analytics
from core.datatypes import Hostname, Link, Element

class ResolveHostnames(Analytics):

    settings = {
        "frequency": timedelta(minutes=10),
        "name": "ProcessHostname",
        "description": "Resolves hostnames and extracts subdomains",
    }

    ACTS_ON = 'Hostname'
    CUSTOM_FILTER = {}
    EXPIRATION = timedelta(days=1)  # Analysis will expire after 1 day

    @classmethod
    def bulk(cls, hostnames):
        p = ParallelDnsResolver()
        results = p.mass_resolve(hostnames)
        for hostname, result in results.items():
            cls.each(hostname, result)

    @classmethod
    def each(cls, hostname, result):
        h = Hostname.get_or_create(hostname)
        for rtype, results in result.items():
            for rdata in results:
                e = Element.add_text(rdata)
                l = Link.connect(h, e)
                l.add_history(tag=rtype, description='{} record'.format(rtype))

        h.analysis_done(cls.__name__)


class ParallelDnsResolver(object):
    """Will issue a producer-consumer object to bulk-resolve domains"""
    def __init__(self):
        self.queue = Queue()
        self.lock = threading.Lock()
        self.results = {}

    def mass_resolve(self, domains, num_threads=50):
        for d in domains:
            self.queue.put((d.value, 'A'))
            self.queue.put((d.value, 'NS'))

        threads = []
        for _ in xrange(num_threads):
            t = threading.Thread(target=self.consumer)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        return self.results

    def consumer(self):
        while True:
            try:
                hostname, rtype = self.queue.get(False)
            except Exception as e:
                return
            try:
                results = dns.resolver.query(hostname, rtype)
                if results:
                    if hostname not in self.results:
                        self.results[hostname] = {}
                    text_results = []
                    for r in results:
                        if isinstance(r, NS_class):
                            text_results.append(r.target.to_text())
                        elif isinstance(r, A_class):
                            text_results.append(r.to_text())
                        else:
                            logging.error("Unknown record type: {}".format(type(r)))
                    self.results[hostname][rtype] = text_results
            except dns.resolver.NoAnswer, e:
                continue
