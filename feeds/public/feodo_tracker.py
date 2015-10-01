from datetime import datetime, timedelta
import re

from core.db.datatypes import Ip, Hostname
from core.feed import Feed

class FeodoTracker(Feed):

    descriptions = {
                'A': "Hosted on compromised webservers running an nginx proxy on port 8080 TCP forwarding all botnet traffic to a tier 2 proxy node. Botnet traffic usually directly hits these hosts on port 8080 TCP without using a domain name.",
                'B': "Hosted on servers rented and operated by cybercriminals for the exclusive purpose of hosting a Feodo botnet controller. Usually taking advantage of a domain name within ccTLD .ru. Botnet traffic usually hits these domain names using port 80 TCP.",
                'C': "Successor of Feodo, completely different code. Hosted on the same botnet infrastructure as Version A (compromised webservers, nginx on port 8080 TCP or port 7779 TCP, no domain names) but using a different URL structure. This Version is also known as Geodo.",
                'D': "Successor of Cridex. This version is also known as Dridex",
                }

    variants = {
                'A': "Feodo",
                'B': "Feodo",
                'C': "Geodo",
                'D': "Dridex",
                }

    settings = {
        "frequency": timedelta(hours=1),
        "name": "FeodoTracker",
        "source": "https://feodotracker.abuse.ch/feodotracker.rss",
        "description": "Feodo Tracker RSS Feed. This feed shows the latest twenty Feodo C2 servers which Feodo Tracker has identified.",
    }

    def update(self):
        for dict in self.update_xml('item', ["title", "link", "description", "guid"]):
            self.analyze(dict)

    def analyze(self, dict):
        context = dict

        date_string = re.search(r"\((?P<datetime>[\d\- :]+)\)", dict['title']).group('datetime')
        try:
            context['date_added'] = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

        g = re.match(r'^Host: (?P<host>.+), Version: (?P<version>\w)', dict['description'])
        g = g.groupdict()
        context['version'] = g['version']
        context['description'] = FeodoTracker.descriptions[g['version']]
        context['subfamily'] = FeodoTracker.variants[g['version']]
        context['source'] = self.name
        del context['title']

        if re.search(r"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}", g['host']):
            new = Ip.get_or_create(g['host'])
        else:
            new = Hostname.get_or_create(g['host'])
        new.add_context(context)
        new.tag(['dridex', 'malware', 'crimeware', 'banker', 'c2'])
