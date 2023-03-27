import logging
import re
from datetime import datetime, timedelta

from pytz import timezone

from core.common.utils import parse_date_to_utc
from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Hash, Url


class CybercrimeAtmosTracker(Feed):
    default_values = {
        "frequency": timedelta(hours=1),
        "name": "CybercrimeAtmosTracker",
        "source": "http://cybercrime-tracker.net/ccam_rss.php",
        "description": "CyberCrime Atmos Tracker - Latest 20 Atmos binaries",
    }

    def update(self):
        since_last_run = datetime.now(timezone("UTC")) - self.frequency

        for item in self.update_xml(
            "item", ["title", "link", "pubDate", "description"]
        ):
            pub_date = parse_date_to_utc(item["pubDate"])
            if self.last_run is not None:
                if since_last_run > pub_date:
                    continue

            self.analyze(item, pub_date)

    def analyze(self, item, pub_date):  # pylint: disable=arguments-differ
        observable_sample = item["title"]
        context_sample = {}

        context_sample["description"] = "Atmos sample"
        context_sample["first_seen"] = pub_date
        context_sample["source"] = self.name
        context_sample["date_added"] = datetime.utcnow()

        link_c2 = re.search(
            "<a href[^>]+>(?P<url>[^<]+)", item["description"].lower()
        ).group("url")
        observable_c2 = link_c2
        context_c2 = {}
        context_c2["description"] = "Atmos c2"
        context_c2["first_seen"] = pub_date
        context_c2["source"] = self.name
        context_c2["date_added"] = datetime.utcnow()

        try:
            sample = Hash.get_or_create(value=observable_sample)
            sample.add_context(context_sample, dedup_list=["date_added"])
            sample.add_source(self.name)
            sample_tags = ["atmos", "objectives"]
            sample.tag(sample_tags)
        except ObservableValidationError as e:
            logging.error(e)
            return

        try:
            c2 = Url.get_or_create(value=observable_c2)
            c2.add_context(context_c2, dedup_list=["date_added"])
            c2.add_source(self.name)
            c2_tags = ["c2", "atmos"]
            c2.tag(c2_tags)
            sample.active_link_to(c2, "c2", self.name, clean_old=False)
        except ObservableValidationError as e:
            logging.error(e)
            return
