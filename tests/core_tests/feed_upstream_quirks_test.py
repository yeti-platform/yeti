import logging
import unittest
from unittest import mock

from core import database_arango
from core.schemas import observable
from plugins.feeds.public import lolbas, miningpoolstats

RULE = "SigmaHQ/sigma/blob/683b63f8/rules/windows/registry_event_bypass_via_wsreset.yml"
RAW = "https://raw.githubusercontent.com/SigmaHQ/sigma/683b63f8/rules/windows/registry_event_bypass_via_wsreset.yml"


class SigmaRawUrlTest(unittest.TestCase):
    def test_rule_links(self) -> None:
        cases = {
            f"https://github.com/{RULE}": RAW,
            # A fragment or query isn't part of the file's path.
            f"https://github.com/{RULE}#": RAW,
            f"https://github.com/{RULE}?plain=1": RAW,
            f"  https://github.com/{RULE}  ": RAW,
            "https://github.com/o/r/blob/main/rules/x.yaml": "https://raw.githubusercontent.com/o/r/main/rules/x.yaml",
        }
        for link, expected in cases.items():
            with self.subTest(link=link):
                self.assertEqual(lolbas.sigma_raw_url(link), expected)

    def test_links_that_are_not_rule_files(self) -> None:
        for link in (
            # Sftp.exe in LOLBAS links its Sigma detection to a pull request.
            "https://github.com/SigmaHQ/sigma/pull/5414/files",
            "https://github.com/SigmaHQ/sigma",
            "https://github.com/SigmaHQ/sigma/blob/main/README.md",
            "https://gitlab.com/o/r/blob/main/rules/x.yml",
            "not a url",
        ):
            with self.subTest(link=link):
                self.assertIsNone(lolbas.sigma_raw_url(link))

    def test_a_link_that_is_not_a_rule_is_skipped_without_a_request(self) -> None:
        feed = lolbas.LoLBAS(**lolbas.LoLBAS._defaults.copy())
        tool = mock.Mock()
        tool.name = "Sftp.exe"
        previous = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous)
        # Fail at once if a request is made: a mocked response handed to
        # yaml.safe_load() reads forever instead of failing.
        no_request = AssertionError("no request expected for a non-rule link")
        with mock.patch.object(lolbas.LoLBAS, "_make_request", side_effect=no_request):
            with self.assertLogs(level=logging.INFO) as logs:
                feed.process_sigma_rule(
                    tool, {"Sigma": "https://github.com/SigmaHQ/sigma/pull/5414/files"}
                )
        self.assertEqual([r.levelno for r in logs.records], [logging.INFO])
        self.assertIn("not a rule file", logs.output[0])


class MiningPoolStatsTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        previous = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous)

    def test_a_pool_id_that_is_only_a_name_is_skipped_quietly(self) -> None:
        feed = miningpoolstats.MiningPoolStats(
            **miningpoolstats.MiningPoolStats._defaults.copy()
        )
        pools = [
            {"url": "", "pool_id": "superblockchain"},
            {"url": "", "pool_id": "pool.example.com"},
        ]
        with (
            mock.patch.object(
                miningpoolstats.MiningPoolStats,
                "_get_coin_names",
                return_value=["monero"],
            ),
            mock.patch.object(
                miningpoolstats.MiningPoolStats,
                "_extract_pool_urls",
                return_value=iter(pools),
            ),
            self.assertLogs(level=logging.DEBUG) as logs,
        ):
            feed.run()

        self.assertIn("Skipping pool id superblockchain", "\n".join(logs.output))
        self.assertFalse([r for r in logs.records if r.levelno >= logging.ERROR])
        saved = observable.Observable.find(value="pool.example.com")
        self.assertIsNotNone(saved)
