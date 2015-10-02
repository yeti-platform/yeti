from datetime import timedelta
import re
import sys

from core.db.datatypes import Url
from core.feed import Feed

class MalcodeBinaries(Feed):

    settings = {
        "frequency": timedelta(hours=1),
        "name": "MalcodeBinaries",
        "source": "http://malc0de.com/rss/",
        "description": "Updated Feed of Malicious Executables",
    }

    def update(self):
        for dict in self.update_xml('item', ['title', 'description', 'link'], headers={"User-Agent": "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11"}):
            self.analyze(dict)
        return True

    def analyze(self, dict):
        g = re.match(r'^URL: (?P<url>.+), IP Address: (?P<ip>[\d.]+), Country: (?P<country>[A-Z]{2}), ASN: (?P<asn>\d+), MD5: (?P<md5>[a-f0-9]+)$', dict['description'])
        if g:
            context = g.groupdict()
            context['link'] = dict['link']
            context['source'] = self.name
            try:
                d = dict['description'].encode('UTF-8')
                url = Url.get_or_create(context.pop('url'))
                url.add_context(context)
                url.tag(['malware', 'delivery'])
            except UnicodeError:
                sys.stderr.write('Unicode error: %s' % dict['description'])
            except ValueError as e:
                logging.error('Invalid URL: {}'.format(url_string))
