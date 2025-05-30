import unittest

from core import database_arango
from core.config.config import yeti_config
from plugins.feeds.public import (
    abusech_malwarebazaar,
    artifacts,
    attack,
    dfiq,
    elastic,
    et_open,
    feodo_tracker_ip_blocklist,
    hybrid_analysis,
    lolbas,
    malpedia,
    miningpoolstats,
    openphish,
    signaturebase,
    sslblacklist_ja3,
    threatfox,
    timesketch,
    tor_exit_nodes,
    yaraforge,
    yaraify,
)


class FeedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

    def test_feodo_tracker_ip_blocklist(self):
        defaults = feodo_tracker_ip_blocklist.FeodoTrackerIPBlockList._defaults.copy()
        defaults["name"] = "FeodoTrackerIPBlocklist"
        feed = feodo_tracker_ip_blocklist.FeodoTrackerIPBlockList(**defaults)
        feed.run()

    def test_openphish(self):
        defaults = openphish.OpenPhish._defaults.copy()
        defaults["name"] = "OpenPhish"
        feed = openphish.OpenPhish(**defaults)
        feed.run()

    def test_malwarebazaar(self):
        defaults = abusech_malwarebazaar.AbuseCHMalwareBazaaar._defaults.copy()
        defaults["name"] = "AbuseCHMalwareBazaaar"
        feed = abusech_malwarebazaar.AbuseCHMalwareBazaaar(**defaults)
        feed.run()

    def test_lolbas(self):
        defaults = lolbas.LoLBAS._defaults.copy()
        feed = lolbas.LoLBAS(**defaults)
        feed.run()

    def test_threatfox(self):
        defaults = threatfox.ThreatFox._defaults.copy()
        feed = threatfox.ThreatFox(**defaults)
        feed.run()

    @unittest.skipIf(
        yeti_config.get("timesketch", "endpoint") is None, "Timesketch not setup"
    )
    def test_timesketch(self):
        defaults = timesketch.Timesketch._defaults.copy()
        feed = timesketch.Timesketch(**defaults)
        feed.run()

    def test_miningpoolstats(self):
        defaults = miningpoolstats.MiningPoolStats._defaults.copy()
        feed = miningpoolstats.MiningPoolStats(**defaults)
        feed.run()

    def test_attack(self):
        defaults = attack.MitreAttack._defaults.copy()
        feed = attack.MitreAttack(**defaults)
        feed.run()

    def test_hybrid_analysis(self):
        defaults = hybrid_analysis.HybridAnalysis._defaults.copy()
        feed = hybrid_analysis.HybridAnalysis(**defaults)
        feed.run()

    def test_dfiq(self):
        defaults = dfiq.DFIQFeed._defaults.copy()
        feed = dfiq.DFIQFeed(**defaults)
        feed.run()

    def test_forensic_artifacts(self):
        defaults = artifacts.ForensicArtifacts._defaults.copy()
        feed = artifacts.ForensicArtifacts(**defaults)
        feed.run()

    def test_tor_exit_nodes(self):
        defaults = tor_exit_nodes.TorExitNodes._defaults.copy()
        feed = tor_exit_nodes.TorExitNodes(**defaults)
        feed.run()

    def test_sslblacklist_ja3(self):
        defaults = sslblacklist_ja3.SSLBlacklistJA3._defaults.copy()
        feed = sslblacklist_ja3.SSLBlacklistJA3(**defaults)
        feed.run()

    def test_yaraify(self):
        defaults = yaraify.YARAify._defaults.copy()
        feed = yaraify.YARAify(**defaults)
        feed.run()

    def test_malpedia_malware(self):
        defaults = malpedia.MalpediaMalware._defaults.copy()
        feed = malpedia.MalpediaMalware(**defaults)
        feed.run()

    def test_malpedia_actor(self):
        defaults = malpedia.MalpediaActors._defaults.copy()
        feed = malpedia.MalpediaActors(**defaults)
        feed.run()

    def test_et_open(self):
        defaults = et_open.ETOpen._defaults.copy()
        feed = et_open.ETOpen(**defaults)
        feed.run()

    def test_neo23_signaturebase(self):
        defaults = signaturebase.Neo23x0SignatureBase._defaults.copy()
        feed = signaturebase.Neo23x0SignatureBase(**defaults)
        feed.run()

    def test_yara_forge(self):
        defaults = yaraforge.YaraForge._defaults.copy()
        feed = yaraforge.YaraForge(**defaults)
        feed.run()

    def test_elastic(self):
        defaults = elastic.Elastic._defaults.copy()
        feed = elastic.Elastic(**defaults)
        feed.run()
