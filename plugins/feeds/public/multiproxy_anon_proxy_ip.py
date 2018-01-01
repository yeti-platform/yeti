from datetime import timedelta
import logging

from core.feed import Feed
from core.errors import ObservableValidationError
from core.observables import Ip


class MultiProxyAnonIP(Feed):
    default_values = {
        "frequency": timedelta(minutes=60),
        "name": "MultiProxyAnonIP",
        "source": "http://multiproxy.org/txt_anon/proxy.txt",
        "description": "multiproxy.org Anonymous Proxy List (with Port)",
    }

    def update(self):
        for line in self.update_csv(delimiter=':', quotechar=' '):
            self.analyze(line)

        self.source = self.default_values['source']

    def analyze(self, line):
        if not line or line[0].startswith("#"):
            return

        try:
            ip, port = tuple(line)
            context = {
                "port": port,
                "source": self.name
            }

            try:
                ip = Ip.get_or_create(value=ip)
                ip.add_context(context)
                ip.add_source('feed')
                ip.tag(['anonproxy'])
            except ObservableValidationError as e:
                logging.error("Invalid line: {}\nLine: {}".format(e, line))

        except ValueError:
            logging.error("Error unpacking line: {}".format(line))
