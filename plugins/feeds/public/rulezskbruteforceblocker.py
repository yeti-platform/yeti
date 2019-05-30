import logging
from dateutil import parser
from datetime import datetime, timedelta
from core.observables import Ip
from core.feed import Feed
from core.config.config import yeti_config
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
            ip_date = parser.parse(date.replace("# ", ""))
            if ip_date > since_last_run:
                self.analyze(ip, ip_date, line)

    def analyze(self, ip, date, raw):
        context = {}
        context['date_added'] = date
        context['source'] = self.name
        context['raw'] = raw

        try:
            ip = Ip.get_or_create(value=ip)
            ip.add_context(context)
            ip.add_source(self.name)
        except ObservableValidationError as e:
            logging.error(e)
