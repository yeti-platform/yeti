import logging
from datetime import datetime, timedelta

from core import Feed
from core.errors import ObservableValidationError
from core.observables import File, Hash, Url


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

        for index ,line in self.update_csv(delimiter=',',
                                    names=['firstseen', 'url', 'filetype', 'md5', 'sha256', 'signature']
                                    , filter_row='firstseen'):

            self.analyze(line)

    def analyze(self, line):

        md5_obs = False
        sha256_obs = False
        url_obs = False
        malware_file = False

        context = {
            'source': self.name,
        }

        first_seen = line['firstseen']
        url = line['url']
        filetype = line['filetype']
        md5_hash = line['md5']
        sha256_hash = line['sha256']
        signature = line['signature']

        if url:
            try:
                url_obs = Url.get_or_create(value=url)
                if signature != 'None':
                    url_obs.tag(signature)
                url_obs.add_context(context)
                url_obs.add_source(self.name)
            except ObservableValidationError as e:
                logging.error(e)

        if sha256_hash:
            try:
                malware_file = File.get_or_create(
                    value='FILE:{}'.format(sha256_hash))

                malware_file.add_context(context)
                malware_file.tag(filetype)

                sha256_obs = Hash.get_or_create(value=sha256_hash)
                sha256_obs.tag(filetype)
                sha256_obs.add_context(context)
                if signature != 'None':
                    sha256_obs.tag(signature)
            except ObservableValidationError as e:
                logging.error(e)

        if md5_hash:
            try:
                md5_obs = Hash.get_or_create(value=md5_hash)
                md5_obs.add_context(context)
                md5_obs.tag(filetype)

                if signature != 'None':
                    md5_obs.tag(signature)
            except ObservableValidationError as e:
                logging.error(e)

        if malware_file:
            if signature != 'None':
                malware_file.tag(signature)

            if md5_obs:
                malware_file.active_link_to(
                    md5_obs, 'md5', self.name)
            if sha256_obs:
                malware_file.active_link_to(
                    sha256_obs, 'sha256', self.name)

            if url_obs:
                url_obs.active_link_to(malware_file, 'drops', self.name)
