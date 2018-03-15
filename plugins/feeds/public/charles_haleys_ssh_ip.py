from datetime import timedelta
import logging

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError


class CahrlesHaleysSSHIP(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'http://charles.the-haleys.org/ssh_dico_attack_hdeny_format.php/hostsdeny.txt',
        'name': 'CahrlesHaleysSSHIP',
        'description': 'Blocklist.de Mail IP Blocklist: All IP addresses which have been reported as performing SSH brute forcing.'
    }

    def update(self):
        for line in self.update_lines():
            self.analyze(line)

    def analyze(self, line):
        if line.startswith('#'):
            return

        try:
            parts = line.split(':')
            ip = str(parts[1])
            context = {
                'source': self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['blocklist', 'ssh'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
