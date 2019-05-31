
import re
import sys
import logging
from datetime import timedelta
from core.observables import Url, Ip, Hash, AutonomousSystem
from core.feed import Feed
from core.errors import ObservableValidationError

type_map = {
    "ip": Ip,
    "url": Url,
    "md5": Hash,
    "asn": AutonomousSystem,
}

class MalcodeBinaries(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "MalcodeBinaries",
        "source": "http://malc0de.com/rss/",
        "description": "Updated Feed of Malicious Executables",
    }

    def update(self):
        for item in self.update_xml('item', ['title', 'description', 'link'],
            headers={"User-Agent":
                "Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11"
            }):
            self.analyze(item)
        return True

    def analyze(self, item):
        g = re.match(
            r'^URL: (?P<url>.+), IP Address: (?P<ip>[\d.]+), Country: (?P<country>[A-Z]{2}), ASN: (?P<asn>\d+), MD5: (?P<md5>[a-f0-9]+)$',
            item['description'])
        if g:
            context = g.groupdict()
            context['link'] = item['link']
            context['source'] = self.name

            url = False

            try:
                url_string = context.pop('url')
                context['description'] = item['description'].encode('UTF-8')
                url = Url.get_or_create(value=url_string)
                url.add_context(context)
                url.add_source(self.name)
                url.tag(['malware', 'delivery'])
            except UnicodeError:
                sys.stderr.write('Unicode error: %s' % item['description'])
            except ObservableValidationError as e:
                logging.error(e)
            except Exception as e:
                logging.error("UNKNOWN EXCEPTION: {}".format(e))

            for ioc in ('ip', 'md5', 'asn'):
                try:
                    ioc_string = context.pop(ioc)
                    ioc_obs = type_map[ioc].get_or_create(value=ioc_string)
                    ioc_obs.add_context(context)
                    ioc_obs.add_source(self.name)
                    ioc_obs.tag(['malware', 'delivery'])
                    if url:
                        ioc_obs.active_link_to(
                            url, ioc, self.name, clean_old=False)
                except ObservableValidationError as e:
                    logging.error(e)
