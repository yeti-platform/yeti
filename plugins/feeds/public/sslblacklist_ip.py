import logging
from dateutil import parser
from datetime import timedelta, datetime

from core.feed import Feed
from core.observables import Url, Ip
from core.errors import ObservableValidationError

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
                    return

            self.analyze(line, first_seen)

    def analyze(self, line, first_seen):

        obs_ip = False
        date, dst_ip, port = line

        tags = []
        tags.append("potentially_malicious_infrastructure")
        tags.append("c2")

        context = dict(source=self.name)
        context["first_seen"] = first_seen

        try:
            ip = Ip.get_or_create(value=dst_ip)
            ip.add_source(self.name)
            ip.tag(tags)
            ip.add_context(context)
        except ObservableValidationError as e:
            logging.error(e)
            return False

        try:
            _url="https://{dst_ip}:{port}/".format(dst_ip=dst_ip, port=port)
            url_obs = Url.get_or_create(value=_url)
            url_obs.add_source(self.name)
            url_obs.tag(tags)
            url_obs.add_context(context)
            if obs_ip:
                url_obs.active_link_to(obs_ip, 'ip', self.name, clean_old=False)
        except ObservableValidationError as e:
            logging.error(e)
            return False
