import unittest

from core import database_arango
from core.config.config import yeti_config
from plugins.feeds.public import feodo_tracker_ip_blocklist
from plugins.feeds.public import openphish
from plugins.feeds.public import lolbas

class FeedTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        # pass
        database_arango.db.clear()

    def skiptest_feodo_tracker_ip_blocklist(self):
        defaults = feodo_tracker_ip_blocklist.FeodoTrackerIPBlockList._defaults.copy()
        defaults['name'] = 'FeodoTrackerIPBlocklist'
        feed = feodo_tracker_ip_blocklist.FeodoTrackerIPBlockList(**defaults)
        feed.run()

    def skiptest_openphish(self):
        defaults = openphish.OpenPhish._defaults.copy()
        defaults['name'] = 'OpenPhish'
        feed = openphish.OpenPhish(**defaults)
        feed.run()

    def test_lolbas(self):
        defaults = lolbas.LoLBAS._defaults.copy()
        feed = lolbas.LoLBAS(**defaults)
        feed.run()
