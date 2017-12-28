import logging
from datetime import timedelta

from core.observables import Ip
from core.feed import Feed
from core.errors import ObservableValidationError

# Time ranges for BadIp can be specified by y=year, day=d, minute=m, month=M
class BadIPApacheDDOSIP(Feed):
    default_values = {
        'frequency': timedelta(hours=1),
        'source': 'https://www.badips.com/get/list/apacheddos/0?age=1d',
        'name': 'BadIPApacheDDOSIP',
        'description': 'Badips.com is a community based IP blacklist service. This list is known hosts performing DDoS against Web Servers.'
    }

    def update(self):
        # First run will backfill data going back 10 years.
        # Since you can declare date ranges this opens the opportunity to create a first_seen function based on time subtraction
        if self.last_run is None:
            self.source = "https://www.badips.com/get/list/apacheddos/0?age=10y"

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
                ip.tag(['blocklist', 'apache', 'ddos'])
            except ObservableValidationError as e:
                logging.error(e)
        except Exception as e:
            logging.debug(e)
