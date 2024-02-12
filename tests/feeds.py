import unittest

from core import database_arango
from core.config.config import yeti_config
from plugins.feeds.public import (
    artifacts,
    attack,
    dfiq,
    feodo_tracker_ip_blocklist,
    hybrid_analysis,
    lolbas,
    openphish,
    timesketch,
)


class FeedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        database_arango.db.connect(database="yeti")
        # database_arango.db.clear()

    # def test_feodo_tracker_ip_blocklist(self):
    #     defaults = feodo_tracker_ip_blocklist.FeodoTrackerIPBlockList._defaults.copy()
    #     defaults["name"] = "FeodoTrackerIPBlocklist"
    #     feed = feodo_tracker_ip_blocklist.FeodoTrackerIPBlockList(**defaults)
    #     feed.run()

    # def test_openphish(self):
    #     defaults = openphish.OpenPhish._defaults.copy()
    #     defaults["name"] = "OpenPhish"
    #     feed = openphish.OpenPhish(**defaults)
    #     feed.run()

    # def test_lolbas(self):
    #     defaults = lolbas.LoLBAS._defaults.copy()
    #     feed = lolbas.LoLBAS(**defaults)
    #     feed.run()

    # @unittest.skipIf(
    #     yeti_config.get("timesketch", "endpoint") is None, "Timesketch not setup"
    # )
    # def test_timesketch(self):
    #     defaults = timesketch.Timesketch._defaults.copy()
    #     feed = timesketch.Timesketch(**defaults)
    #     feed.run()

    # def test_attack(self):
    #     defaults = attack.MitreAttack._defaults.copy()
    #     feed = attack.MitreAttack(**defaults)
    #     feed.run()

    # def test_hybrid_analysis(self):
    #     defaults = hybrid_analysis.HybridAnalysis._defaults.copy()
    #     feed = hybrid_analysis.HybridAnalysis(**defaults)
    #     feed.run()

    def test_dfiq(self):
        defaults = dfiq.DFIQFeed._defaults.copy()
        feed = dfiq.DFIQFeed(**defaults)
        feed.run()

    # def test_forensic_artifacts(self):
    #     defaults = artifacts.ForensicArtifacts._defaults.copy()
    #     feed = artifacts.ForensicArtifacts(**defaults)
    #     feed.run()
