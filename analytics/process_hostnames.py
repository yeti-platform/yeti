from datetime import timedelta
import threading
import logging
from Queue import Queue, Empty

import dns
from dns.resolver import NoAnswer, NXDOMAIN, Timeout, NoNameservers
from dns.rdtypes.ANY.NS import NS as NS_class
from dns.rdtypes.IN.A import A as A_class

from core.analytics import ScheduledAnalytics
from core.database import Link
from core.observables import Hostname, Observable
from core.helpers import is_subdomain
from core.errors import ObservableValidationError


class ProcessHostnames(ScheduledAnalytics):

    settings = {
        "frequency": timedelta(minutes=2),
        "name": "ProcessHostnames",
        "description": "Resolves hostnames and extracts subdomains",
        "lock": False,
    }

    ACTS_ON = 'Hostname'
    EXPIRATION = timedelta(days=1)  # Analysis will expire after 1 day

    @classmethod
    def bulk(cls, hostnames):
        p = ParallelDnsResolver()
        results = p.mass_resolve(hostnames)

    @classmethod
    def each(cls, hostname, rtype, results):
        h = Hostname.get_or_create(value=hostname)
        domain = is_subdomain(hostname)
        if domain:
            d = Hostname.get_or_create(value=domain)
            d.add_source("analytics")
            l = Link.connect(h, d)
            l.add_history(tag='domain')

        for rdata in results:
            logging.info("{} resolved to {} ({} record)".format(h.value, rdata, rtype))
            try:
                e = Observable.add_text(rdata)
                e.add_source("analytics")
                l = Link.connect(h, e)
                l.add_history(tag=rtype, description='{} record'.format(rtype))
            except ObservableValidationError as e:
                logging.error("{} is not a valid datatype".format(rdata))

        h.analysis_done(cls.__name__)


class ParallelDnsResolver(object):
    """Will issue a producer-consumer object to bulk-resolve domains"""
    def __init__(self):
        self.queue = Queue(1000)
        self.lock = threading.Lock()
        self.results = {}

    def mass_resolve(self, domains, num_threads=50):
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
                logging.debug("Getting observable")
                hostname, rtype = self.queue.get(True, 5)
                logging.debug("Got {}".format(hostname))
            except Empty:
                logging.debug("Empty! Bailing")
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
                    ProcessHostnames.each(hostname, rtype, text_results)
            except NoAnswer:
                continue
            except NXDOMAIN:
                continue
            except Timeout:
                continue
            except NoNameservers:
                continue
            except Exception as e:
                import traceback
                logging.error(traceback.print_exc())
                logging.error("Unknown error occurred while owrking on {} ({})".format(hostname, rtype))
                logging.error("\nERROR: {}".format(hostname, rtype, e))
                continue
