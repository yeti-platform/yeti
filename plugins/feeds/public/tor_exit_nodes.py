import logging
from datetime import timedelta, datetime

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
        feed = self._make_request().text

        start = feed.find("<!-- __BEGIN_TOR_NODE_LIST__ //-->") + len(
            "<!-- __BEGIN_TOR_NODE_LIST__ //-->"
        )
        end = feed.find("<!-- __END_TOR_NODE_LIST__ //-->")

        feed_raw = (
            feed[start:end]
            .replace("\n", "")
            .replace("<br />", "\n")
            .replace("&gt;", ">")
            .replace("&lt;", "<")
        )

        feed = feed_raw.split("\n")
        if len(feed) > 10:
            self.status = "OK"

        feed = self._temp_feed_data_compare(feed_raw)

        for line in feed:
            self.analyze(line)

        return True

    def analyze(self, line):

        fields = line.split("|")

        if len(fields) < 8:
            return

        context = {
            "name": fields[1],
            "router-port": fields[2],
            "directory-port": fields[3],
            "flags": fields[4],
            "version": fields[6],
            "contactinfo": fields[7],
            "source": self.name,
            "description": "Tor exit node: %s (%s)" % (fields[1], fields[0]),
            "date_added": datetime.utcnow(),
        }

        try:
            ip = Ip.get_or_create(value=fields[0])
            ip.add_context(context, dedup_list=["date_added"])
            ip.add_source(self.name)
            ip.tag(["tor"])
        except ObservableValidationError as e:
            logging.error(e)
