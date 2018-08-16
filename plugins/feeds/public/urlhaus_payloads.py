import logging
from datetime import timedelta

from core import Feed
from core.errors import ObservableValidationError
from core.observables import Url, File, Hash


class UrlhausPayloads(Feed):
    default_values = {
        "frequency":
            timedelta(hours=1),
        "name":
            "UrlHausPayloads",
        "source":
            "https://urlhaus.abuse.ch/downloads/payloads/",
        "description":
            "URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.",
    }

    def update(self):
        for line in self.update_csv(delimiter=',', quotechar='"'):
            self.analyze(line)

    def analyze(self, item):

        if not item or item[0].startswith("#"):
            return

        first_seen, url, filetype, md5, sha256, signature = item

        if url:
            try:
                url_obs = Url.get_or_create(value=url)
                context = {
                    'first_seen': first_seen,
                    'source': self.name
                }
                if signature != 'None':
                    url_obs.tag(signature)
                url_obs.add_context(context)
                url_obs.add_source('feed')

                context_malware = {
                    'source': self.name
                }

                malware_file = File.get_or_create(
                    value='FILE:{}'.format(sha256))

                malware_file.add_context(context_malware)

                sha256 = Hash.get_or_create(value=sha256)
                sha256.tag(filetype)
                sha256.add_context(context_malware)
                if signature != 'None':
                    sha256.tag(signature)

                md5 = Hash.get_or_create(value=md5)
                md5.add_context(context_malware)
                md5.tag(filetype)

                if signature != 'None':
                    md5.tag(signature)

                malware_file.active_link_to(md5, 'md5', self.name)

                malware_file.active_link_to(sha256, 'sha256', self.name)
                if signature != 'None':
                    malware_file.tag(signature)
                malware_file.tag(filetype)

                url_obs.active_link_to(malware_file, 'drops', self.name)

            except ObservableValidationError as e:
                logging.error(e)
