import logging
from datetime import timedelta

from core.feed import Feed
from core.observables import Ip
from core.errors import ObservableValidationError


class TorExitNodes(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "TorExitNodes",
        "source": "https://www.dan.me.uk/tornodes",
        "description": "Tor exit nodes",
    }

    def update(self):
        feed = self._make_requests().text

        start = feed.find('<!-- __BEGIN_TOR_NODE_LIST__ //-->') + len(
            '<!-- __BEGIN_TOR_NODE_LIST__ //-->')
        end = feed.find('<!-- __END_TOR_NODE_LIST__ //-->')

        feed_raw = feed[start:end].replace(
            '\n', '').replace('<br />', '\n').replace('&gt;', '>').replace(
                '&lt;', '<')

        feed = feed_raw.split('\n')
        if len(feed) > 10:
            self.status = "OK"

        feed = self._temp_feed_data_compare(feed_raw)

        for line in feed:
            self.analyze(line)
        return True

    def analyze(self, line):

        fields = line.split('|')

        if len(fields) < 8:
            return

        context = {}
        ip = fields[0]
        context['name'] = fields[1]
        context['router-port'] = fields[2]
        context['directory-port'] = fields[3]
        context['flags'] = fields[4]
        context['version'] = fields[6]
        context['contactinfo'] = fields[7]

        context['description'] = "Tor exit node: %s (%s)" % (
            context['name'], ip)
        context['source'] = self.name
        try:
            ip = Ip.get_or_create(value=fields[0])
            ip.add_context(context)
            ip.add_source(self.name)
            ip.tag(['tor'])
        except ObservableValidationError as e:
            logging.error(e)
