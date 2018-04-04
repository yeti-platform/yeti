import re
from datetime import timedelta

from core import Feed
import logging

from core.observables import Hostname, Ip


class BambenekOsintIpmaster(Feed):
    default_values = {
        "frequency":
            timedelta(minutes=60),
        "name":
            "BambenekOsintIpmaster",
        "source":
            "http://osint.bambenekconsulting.com/feeds/c2-masterlist.txt",
        "description":
            "Master Feed of known, active and non-sinkholed C&Cs indicators (Bambenek)",
    }
    pattern = 'Master Indicator Feed for (\w+) non-sinkholed domains'
    reg = re.compile(pattern)

    def update(self):
        for line in self.update_lines():
            print(line)
            self.analyze(line)

    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return

        tokens = line.split(',')
        c2_domain = []
        ips_c2 = []
        names_servers = []
        ip_names_servers = []
        context_feed = []
        if len(tokens) == 6:
            c2_domain = tokens[0]
            ips_c2 = tokens[1].split('|')
            names_servers = tokens[2].split('|')
            ip_names_servers = tokens[3].split('|')
            context_feed = tokens[4]

            m = BambenekOsintIpmaster.reg.match(context_feed)
            malware_family = ''
            if m:
                malware_family = m.group(1)

            context = {
                "status": context_feed,
                "name servers": names_servers,
                "source": self.name
            }
            tags = [malware_family]
            c2 = None
            if c2_domain:
                c2 = Hostname.get_or_create(value=c2_domain)
                c2.add_context(context)
                c2.tag(tags)

                for ip in ips_c2:
                    if ip:
                        ip_obs = Ip.get_or_create(value=ip)
                        ip_obs.tag(tags)
                        if c2:
                            c2.active_link_to(ip_obs, "IP", self.source)

            for name_server in names_servers:
                if name_server:
                    ns_obs = Hostname.get_or_create(value=name_server)
                    c2.active_link_to(ns_obs, 'NS', self.source)
                    ns_obs.tag(tags)
                    ns_obs.add_context(context)

            for ip_ns in ip_names_servers:
                if ip_ns:
                    ip_ns_obs = Ip.get_or_create(value=ip_ns)
                    c2.active_link_to(ip_ns_obs, 'IP NS', self.source)
                    ip_ns_obs.tag(tags)
                    ip_ns_obs.add_context(context)
        else:
            logging.error('Parsing error in line: %s' % line)
