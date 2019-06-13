import logging
from datetime import datetime, timedelta

from dateutil import parser

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import AutonomousSystem, Ip, Observable, Url

TYPE_DICT = {
    "Payment Site": ['payment_site'],
    "C2": ["c2"],
    "Distribution Site": ["payload_delivery", "driveby"],
}


class RansomwareTracker(Feed):

    default_values = {
        "frequency": timedelta(minutes=20),
        "name": "RansomwareTracker",
        "source": "http://ransomwaretracker.abuse.ch/feeds/csv/",
        "description":
            "Ransomware Tracker offers various types of blocklists that allows you to block Ransomware botnet C&C traffic.",
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

            self.analyze(line)

    def analyze(self, line):
        first_seen, _type, family, hostname, url, status, registrar, ips, asns, countries = line

        tags = []
        tags += TYPE_DICT[_type]
        tags.append(family.lower())

        context = {
            "first_seen": parser.parse(first_seen),
            "status": status,
            "registrar": registrar,
            "countries": countries.split("|"),
            "asns": asns.split("|"),
            "source": self.name
        }

        url_obs = False
        hostname_obs = False
        try:
            url_obs = Url.get_or_create(value=url.rstrip())
            url_obs.add_context(context)
            url_obs.tag(tags)
        except (ObservableValidationError, UnicodeEncodeError) as e:
            logging.error("Invalid line: {}\nLine: {}".format(e, line))

        try:
            hostname = Observable.add_text(hostname)
            hostname.tag(tags + ['blocklist'])
        except (ObservableValidationError, UnicodeEncodeError) as e:
            logging.error("Invalid line: {}\nLine: {}".format(e, line))

        for ip in ips.split("|"):
            if ip != hostname and ip is not None and ip != '':
                try:
                    ip_obs = Ip.get_or_create(value=ip)
                    ip_obs.active_link_to(
                        (url_obs, hostname), "ip", self.name, clean_old=False)
                except (ObservableValidationError, UnicodeEncodeError) as e:
                    logging.error("Invalid Observable: {}".format(e))

                for asn in asns.split("|"):
                    try:
                        asn_obs = AutonomousSystem.get_or_create(value=asn)
                        asn_obs.active_link_to(
                            (hostname, ip_obs),
                            "asn",
                            self.name,
                            clean_old=False)

                    except (ObservableValidationError, UnicodeEncodeError) as e:
                        logging.error("Invalid Observable: {}".format(e))
