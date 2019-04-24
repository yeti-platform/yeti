import csv
import logging
import requests
from datetime import datetime, timedelta
from core.observables import Hash
from core.feed import Feed
from core.config.config import yeti_config
from core.errors import ObservableValidationError

class ViruSign(Feed):

    default_values = {
        "frequency": timedelta(hours=24),
        "name": "ViruSign",
        "source": "https://www.virusign.com/get_hashlist.php?ssdeep&imphash&sha256&sha1&md5&n=ANY&start_date={date}&end_date={date}",
        "description": "This feed contains daily list of hashes from ViruSign",
    }

    def update(self):
        today = datetime.now().strftime("%Y-%m-%d")
        try:
            r = requests.get(self.source.format(date=today), headers={"User-Agent": "yeti-project"})
            if r.ok:
                reader = csv.reader(r.content.splitlines(), quotechar='"')
                for line in reader:
                    self.analyze(line)
        except Exception as e:
            logging.error(e)

    def analyze(self, line):
        ssdeep, imphash, sha256, sha1, md5 = line
        context = {}
        context['date_added'] = datetime.now()
        context['source'] = self.name

        try:
            md5_data = Hash.get_or_create(value=md5)
            if md5_data.new is True or self.name not in md5_data.sources:
                md5_data.add_context(context)
                md5_data.add_source(self.name)
        except ObservableValidationError as e:
            logging.error(e)

        try:
            sha1_data = Hash.get_or_create(value=sha1)
            if sha1_data.new is True or self.name not in sha1_data.sources:
                sha1_data.add_context(context)
                sha1_data.add_source(self.name)
        except ObservableValidationError as e:
            logging.error(e)

        try:
            sha256_data = Hash.get_or_create(value=sha256)
            if sha256_data.new is True or self.name not in sha256_data.sources:
                sha256_data.add_context(context)
                sha256_data.add_source(self.name)
        except ObservableValidationError as e:
            logging.error(e)

        try:
            md5_data.active_link_to(sha1_data, 'sha1', self.name)
            md5_data.active_link_to(sha256_data, 'sha256', self.name)
        except Exception as e:
            logging.error(e)
