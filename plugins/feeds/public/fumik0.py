import logging
from datetime import timedelta, datetime

from core.errors import ObservableValidationError
from core.feed import Feed
from core.observables import Url, Ip, Hash


class Fumik0Tracker(Feed):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "Fumik0Tracker",
        "source": "https://tracker.fumik0.com/api/get-samples",
        "description": "This feed contains md5/sha1/sha256/urls",
    }

    def update(self):

        for index, block in self.update_json(filter_row="first_seen"):
            self.analyze(block)

    def analyze(self, block):  # pylint: disable=arguments-differ

        """
        block example
           {u"first_seen": u"2019-03-13 14:38:12",
             u"hash": {u"md5": u"e1513c048e520e8d5fc5999d82994ea7",
                       u"sha1": u"f09f66c3bd4cd54cc030b7d102be32376fd993b5",
                       u"sha256": u"bbb450f1f68735054af6d1c64bd3a7e62f9977d40eeb286340d8bc1dac6f7e7e"},
             u"hash_seen": 1,
             u"id": u"5c8915d47a324f51d460e8e5",
             u"sample": {u"name": u"vdvdv.exe", u"size": u"600576"},
             u"server": {u"AS": u"AS197695",
                         u"country": u"ru",
                         u"ip": u"37.140.192.146",
                         u"url": u"byhlavash.chimkent.su/vdvdv.exe"}}
        """
        url = block["server"]["url"]
        if "http" not in url:
            url = "http://" + url
        context = {}
        context["first_seen"] = block["first_seen"]
        context["as"] = block["server"]["AS"]
        context["country"] = block["server"]["country"]
        context["ip"] = block["server"]["ip"]
        context["source"] = self.name
        context["md5"] = block["hash"]["md5"]
        context["sha1"] = block["hash"]["sha1"]
        context["sha256"] = block["hash"]["sha256"]
        context["date_added"] = datetime.utcnow()

        url_data = None
        try:
            url_data = Url.get_or_create(value=url)
            url_data.add_context(context, dedup_list=["date_added"])
            url_data.add_source(self.name)
        except ObservableValidationError as e:
            logging.error(e)

        if block.get("server", {}).get("ip", ""):
            try:
                ip = Ip.get_or_create(value=block["server"]["ip"])
                ip.add_context(context, dedup_list=["date_added"])
                ip.add_source(self.name)
                if url_data:
                    url_data.active_link_to(ip, "ip", self.name, clean_old=False)
            except ObservableValidationError as e:
                logging.error(e)

        if block.get("hash", []):
            # md5, sha1, sha256
            for hash_type in block["hash"]:
                try:
                    hash_data = Hash.get_or_create(value=block["hash"][hash_type])
                    hash_data.add_context(context, dedup_list=["date_added"])
                    hash_data.add_source(self.name)
                    if url_data:
                        url_data.active_link_to(
                            hash_data, "hash", self.name, clean_old=False
                        )
                except ObservableValidationError as e:
                    logging.error(e)
