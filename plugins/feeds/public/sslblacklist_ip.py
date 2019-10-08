import logging
from datetime import datetime, timedelta

from dateutil import parser

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Ip, Url


class SSLBlackListIP(Feed):

    default_values = {
        "frequency": timedelta(minutes=1440),
        "name": "SSLBlackListIPs",
        "source": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "description": "abuse.ch SSLBL Botnet C2 IP Blacklist (CSV)",
    }

    def update(self):

        since_last_run = datetime.now() - self.frequency

        for line in self.update_csv(delimiter=',', quotechar='"'):
            if not line or line[0].startswith("#"):
                continue

            first_seen = parser.parse(line[0])
            if self.last_run is not None:
                if since_last_run > first_seen:
                    continue

            self.analyze(line, first_seen)

    def analyze(self, line, first_seen):

        _, dst_ip, port = line
        ip_obs = False
        tags = ["potentially_malicious_infrastructure", "c2"]

        context = dict(source=self.name)
        context["first_seen"] = first_seen

        try:
            ip_obs = Ip.get_or_create(value=dst_ip)
            ip_obs.add_source(self.name)
            ip_obs.tag(tags)
            ip_obs.add_context(context)
        except ObservableValidationError as e:
            logging.error(e)
            return False

        try:
            _url = "https://{dst_ip}:{port}/".format(dst_ip=dst_ip, port=port)
            url = Url.get_or_create(value=_url)
            url.add_source(self.name)
            url.tag(tags)
            url.add_context(context)
            if ip_obs:
                url.active_link_to(ip_obs, 'ip', self.name)
        except ObservableValidationError as e:
            logging.error(e)
            return False
