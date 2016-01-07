from datetime import timedelta

from core.observables import Hostname
from core.feed import Feed


class DynamicDomains(Feed):

    settings = {
        "frequency": timedelta(hours=24),
        "name": "DynamicDomains",
        "source": "http://mirror1.malwaredomains.com/files/dynamic_dns.txt",
        "description": "Malwaredomains.com Dynamic Domains list",
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        line = line.strip()
        sline = line.split()

        try:
            if line[0] != '#':
                hostname = sline[0]

                context = {}
                context['source'] = self.name
                context['provider'] = sline[0]

                hostname = Hostname.get_or_create(value=hostname)
                hostname.add_context(context)
                hostname.add_source("feed")
                hostname.tag('dyndns')
        except Exception:
            pass
