import idna

from core.observables import Observable
from core.helpers import is_hostname
from core.errors import ObservableValidationError


class Hostname(Observable):

    def clean(self):
        """Performs some normalization on hostnames before saving to the db"""
        try:
            self.value = self.normalize(self.value)
        except Exception:
            raise ObservableValidationError("Invalid hostname: {}".format(self.value))

    @staticmethod
    def normalize(hostname):
        if not is_hostname(hostname):
            raise ObservableValidationError("Invalid Hostname (is_hostname={}): {}".format(is_hostname(hostname), hostname))
        if hostname.endswith('.'):
            hostname = hostname[:-1]
        hostname = unicode(idna.encode(hostname.lower()))
        return hostname
