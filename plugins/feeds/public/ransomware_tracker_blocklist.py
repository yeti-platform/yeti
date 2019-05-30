from datetime import timedelta
import logging

from core.feed import Feed
from core.observables import Url, Ip, Observable, AutonomousSystem
from core.errors import ObservableValidationError

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
        for line in self.update_csv(delimiter=',', quotechar='"'):
            self.analyze(line)

    def analyze(self, line):

        if not line or line[0].startswith("#"):
            return

        date, _type, family, hostname, url, status, registrar, ips, asns, countries = tuple(
            line)

        tags = []
        tags += TYPE_DICT[_type]
        tags.append(family.lower())

        context = {
            "first_seen": date,
            "status": status,
            "registrar": registrar,
            "countries": countries.split("|"),
            "asns": asns.split("|"),
            "source": self.name
        }

        try:
            url = Url.get_or_create(value=url.rstrip())
            url.add_context(context)
            url.tag(tags)

            hostname = Observable.add_text(hostname)
            hostname.tag(tags + ['blocklist'])

            for ip in ips.split("|"):
                if ip != hostname and ip is not None and ip != '':
                    try:
                        ip_obs = Ip.get_or_create(value=ip)
                        ip_obs.active_link_to(
                            hostname,
                            "IP",
                            self.name,
                            clean_old=False)
                    except ObservableValidationError as e:
                        logging.error("Invalid Observable: {}".format(e))

                    for asn in asns.split("|"):
                        try:
                            asn_obs = AutonomousSystem.get_or_create(value=asn)
                            asn_obs.active_link_to(
                                (hostname, ip_obs),
                                "ASN",
                                self.name,
                                clean_old=False)
                        except ObservableValidationError as e:
                            logging.error("Invalid Observable: {}".format(e))

        except ObservableValidationError as e:
            logging.error("Invalid line: {}\nLine: {}".format(e, line))
