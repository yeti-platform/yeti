from __future__ import unicode_literals

from datetime import timedelta, datetime
import threading
import logging
from Queue import Queue, Empty

import dns
from dns.resolver import NoAnswer, NXDOMAIN, Timeout, NoNameservers
from dns.rdtypes.ANY.NS import NS as NS_class
from dns.rdtypes.IN.A import A as A_class

from core.analytics import ScheduledAnalytics
from core.observables import Hostname, Observable
from core.errors import ObservableValidationError


class ResolveHostnames(ScheduledAnalytics):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "ResolveHostnames",
        "description": "Resolves hostnames and extracts subdomains",
    }

    ACTS_ON = 'Hostname'
    EXPIRATION = timedelta(days=3)  # Analysis will expire after 1 day

    def bulk(self, hostnames):
        if 20 < datetime.utcnow().hour or datetime.utcnow().hour < 8:
            p = ParallelDnsResolver()
            p.mass_resolve(hostnames)

    @classmethod
    def each(cls, hostname, rtype=None, results=[]):
        generated = []
        h = Hostname.get_or_create(value=hostname.value)

        for rdata in results:
            logging.debug(
                "{} resolved to {} ({} record)".format(h.value, rdata, rtype))
            try:
                e = Observable.add_text(rdata)
                e.add_source("analytics")
                generated.append(e)
            except ObservableValidationError as e:
                logging.error("{} is not a valid datatype".format(rdata))

        h.active_link_to(
            generated, "{} record".format(rtype), "ResolveHostnames")

        h.analysis_done(cls.__name__)
        return generated


class ParallelDnsResolver(object):
    """Will issue a producer-consumer object to bulk-resolve domains"""

    def __init__(self):
        self.queue = Queue(1000)
        self.lock = threading.Lock()
        self.results = {}
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2

    def mass_resolve(self, domains, num_threads=100):
        threads = []
        for _ in xrange(num_threads):
            logging.debug("Starting thread {}".format(_))
            t = threading.Thread(target=self.consumer)
            t.start()
            threads.append(t)

        for d in domains:
            logging.debug("Putting {} in resolver queue".format(d))
            self.queue.put((d.value, 'A'), True)
            # Avoid ns1.ns1.ns1.domain.com style recursions
            if d.value.count('.') <= 2:
                self.queue.put((d.value, 'NS'), True)

        for t in threads:
            t.join()

        return self.results

    def consumer(self):
        while True:
            try:
                hostname, rtype = self.queue.get(True, 5)
            except Empty:
                logging.debug("Empty! Bailing")
                return
            try:
                logging.debug("Starting work on {}".format(hostname))
                results = self.resolver.query(hostname, rtype)
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
                            logging.error(
                                "Unknown record type: {}".format(type(r)))
                    hostname = Hostname(value=hostname)
                    ResolveHostnames.each(hostname, rtype, text_results)
            except NoAnswer:
                continue
            except NXDOMAIN:
                continue
            except Timeout:
                logging.debug("Request timed out for {}".format(hostname))
                continue
            except NoNameservers:
                continue
            except Exception as e:
                import traceback
                logging.error(
                    "Unknown error occurred while working on {} ({})".format(
                        hostname, rtype))
                logging.error("\nERROR: {}".format(hostname, rtype, e))
                logging.error(traceback.print_exc())

                continue
