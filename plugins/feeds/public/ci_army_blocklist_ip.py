from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class CIArmyBlocklistip(Feed):
    default_values = {
        'frequency': timedelta(hours=4),
        'source': 'http://cinsscore.com/list/ci-badguys.txt',
        'name': 'CIArmyBlocklistip',
        'description': 'CINS Army IP Blocklist: The CINS Army list is a subset of the CINS Active Threat Intelligence ruleset, and consists of IP addresses that meet one of two basic criteria: 1) The IPs recent Rogue Packet score factor is very poor, or 2) The IP has tripped a designated number of trusted alerts across a given number of our Sentinels deployed around the world'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            line = line.strip()
            parts = line.split()

            ip = str(parts[0]).strip()
            context = {
                'source': self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['blocklist'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
