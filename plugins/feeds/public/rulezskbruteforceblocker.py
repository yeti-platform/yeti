import logging
from dateutil import parser
from datetime import datetime, timedelta

from core.observables import Ip
from core.feed import Feed

from core.errors import ObservableValidationError

class RulezSKBruteforceBlocker(Feed):

    default_values = {
        "frequency": timedelta(hours=24),
        "name": "RulezSKBruteforceBlocker",
        "source": "http://danger.rulez.sk/projects/bruteforceblocker/blist.php",
        "description": "This feed contains daily list of IPs from rules.sk",
    }

    def update(self):
        since_last_run = datetime.now() - self.frequency
        r = self._make_request(headers={"User-Agent": "yeti-project"})
        lines = r.content.splitlines()[1:-1]
        for line in lines:
            ip, date, count, id = filter(None, line.split("\t"))
            first_seen = parser.parse(date.replace("# ", ""))
            if self.last_run is not None:
                if since_last_run > first_seen:
                    return

            self.analyze(ip, first_seen, line)

    def analyze(self, ip, first_seen, raw):
        context = {}
        context['first_seen'] = first_seen
        context['source'] = self.name
        context['raw'] = raw

        try:
            ip = Ip.get_or_create(value=ip)
            ip.add_context(context)
            ip.add_source(self.name)
        except ObservableValidationError as e:
            logging.error(e)
