from datetime import timedelta

from core.feed import Feed
from core.observables import Hostname
from core.errors import ObservableValidationError

class DynamicDomains(Feed):

    default_values = {
        "frequency": timedelta(hours=24),
        "name": "DynamicDomains",
        "source": "http://mirror1.malwaredomains.com/files/dynamic_dns.txt",
        "description": "Malwaredomains.com Dynamic Domains list",
    }

    def update(self):
        for line in self.update_lines():
            if line[0].startswith('#'):
                continue

            self.analyze(line)

    def analyze(self, line):
        line = line.strip()
        sline = line.split()

        hostname = sline[0]

        context = {}
        context['source'] = self.name
        context['provider'] = sline[0]

        try:
            hostname = Hostname.get_or_create(value=hostname)
            hostname.add_context(context)
            hostname.add_source(self.name)
            hostname.tag('dyndns')
        except ObservableValidationError:
            pass
