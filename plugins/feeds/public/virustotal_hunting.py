import json
from datetime import timedelta

from core import Feed
from core.observables import Hash
from core.config.config import yeti_config
import logging


class VirusTotalHunting(Feed):

    default_values = {
        "frequency": timedelta(minutes=5),
        "name": "VirusTotalHunting",
        "source": "https://www.virustotal.com/intelligence/hunting/",
        "description": "Feed of hunting of VirusTotal",

    }

    settings = {
        'vt_url_hunting': {
            'name': 'VT Url Hunting',
            'description': 'on Virus Total you can make a feed in json or xml in tab hunting'
        }
    }

    def update(self):
        api_key = yeti_config.get('vt', 'key')

        if api_key:
            self.source = 'https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=%s' % api_key
            for item in self.update_json()['notifications']:
                self.analyze(item)
        else:
            logging.error("Your VT API key is not set in the confile file")

    def analyze(self, item):
        tags = []
        json_string = json.dumps(item)
        context = {'source': self.name}

        sha256 = Hash.get_or_create(value=item['sha256'])

        md5 = Hash.get_or_create(value=item['md5'])

        sha1 = Hash.get_or_create(value=item['sha1'])

        sha256.active_link_to(md5, 'md5', self.name)
        sha256.active_link_to(sha1, 'sha1', self.name)

        tags.append(item['ruleset_name'])
        tags.append(item['type'])

        context['raw'] = json_string

        context['score vt'] = '%s/%s' % (item['positives'], item['total'])

        sha256.add_context(context)
        sha256.tag(tags)

        sha1.add_context(context)
        sha1.tag(tags)

        md5.add_context(context)
        md5.tag(tags)