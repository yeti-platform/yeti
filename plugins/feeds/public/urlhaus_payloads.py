import logging
from dateutil import parser
from datetime import timedelta, datetime

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Url, File, Hash


class UrlHausPayloads(Feed):
    default_values = {
        "frequency": timedelta(hours=1),
        "name": "UrlHausPayloads",
        "source": "https://urlhaus.abuse.ch/downloads/payloads/",
        "description":
            "URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.",
    }

    def update(self):
        since_last_run = datetime.utcnow() - self.frequency

        for line in self.update_csv(delimiter=',', quotechar='"'):
            if not line or line[0].startswith("#"):
                continue

            first_seen, url, filetype, md5, sha256, signature = line
            first_seen = parser.parse(first_seen)
            if self.last_run is not None:
                if since_last_run > first_seen:
                    return

            self.analyze(first_seen, url, filetype, md5, sha256, signature)

    def analyze(self, first_seen, url, filetype, md5, sha256, signature):

        md5_obs = False
        sha256_obs = False
        url_obs = False
        malware_file = False

        context = {
            'source': self.name
        }

        if url:
            try:
                url_obs = Url.get_or_create(value=url)
                if signature != 'None':
                    url_obs.tag(signature)
                url_obs.add_context(context)
                url_obs.add_source(self.name)
            except ObservableValidationError as e:
                logging.error(e)

        if sha256:
            try:
                malware_file = File.get_or_create(
                    value='FILE:{}'.format(sha256))

                malware_file.add_context(context)
                malware_file.tag(filetype)

                sha256_obs = Hash.get_or_create(value=sha256)
                sha256_obs.tag(filetype)
                sha256_obs.add_context(context)
                if signature != 'None':
                    sha256_obs.tag(signature)
            except ObservableValidationError as e:
                logging.error(e)

        if md5:
            try:
                md5_obs = Hash.get_or_create(value=md5)
                md5_obs.add_context(context)
                md5_obs.tag(filetype)

                if signature != 'None':
                    md5_obs.tag(signature)
            except ObservableValidationError as e:
                logging.error(e)

        if malware_file:
            if signature != 'None':
                malware_file.tag(signature)

            try:
                if md5_obs:
                    malware_file.active_link_to(
                        md5_obs, 'md5', self.name)
                if sha256_obs:
                    malware_file.active_link_to(
                        sha256_obs, 'sha256', self.name)
            except Exception as e:
                logging.error(e)

            if url_obs:
                url_obs.active_link_to(malware_file, 'drops', self.name)
