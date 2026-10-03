import datetime
import importlib
import unittest
from unittest import mock

import pandas as pd

from core import database_arango
from core.schemas.observables import asn, hostname, ipv4, ja3, url
from plugins.feeds.public import (
    abuseipdb,
    dataplane_dnsrd,
    dataplane_dnsrdany,
    dataplane_dnsversion,
    dataplane_proto41,
    dataplane_sipinvite,
    dataplane_sipquery,
    dataplane_smtpdata,
    rulezskbruteforceblocker,
    sslblacklist_ja3,
    tor_exit_nodes,
)

# The module name has a hyphen, so an import statement can't load it.
azorult_tracker = importlib.import_module("plugins.feeds.public.azorult-tracker")

DAY_1 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
DAY_2 = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)


def dataplane_row(ipaddr: str, lastseen: str, firstseen: str | None = None):
    """Builds a row the way the Dataplane feeds' run() passes it to analyze()."""
    row = {"ASN": "64500", "ASname": "EXAMPLE-AS", "ipaddr": ipaddr}
    if firstseen is not None:
        # DataplaneProto41 only; its run() leaves firstseen a string.
        row["firstseen"] = firstseen
    row["lastseen"] = pd.Timestamp(lastseen)
    row["category"] = "test"
    return pd.Series(row)


class FeedContextTest(unittest.TestCase):
    """Feeds whose context holds a value that changes between runs (#1375).

    The tests hand a feed's analyze() the same context twice with only that
    value changed, and check that the feed's entry is updated instead of a
    second one being appended."""

    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

    def feed_contexts(self, obs_class, value: str, source: str) -> list[dict]:
        obs = obs_class.find(value=value)
        assert obs is not None
        return [context for context in obs.context if context["source"] == source]

    def test_dataplane_dnsrd_same_ip_keeps_one_context(self) -> None:
        """Tests that a Dataplane row processed again with a newer lastseen
        updates the IP and ASN contexts instead of appending to them.

        lastseen differs on every Dataplane run, so while it was compared each
        run added an entry to the IP and to its AS."""
        feed = dataplane_dnsrd.DataplaneDNSRecursive(
            **dataplane_dnsrd.DataplaneDNSRecursive._defaults.copy()
        )
        feed.analyze(dataplane_row("203.0.113.1", "2026-01-01 00:00:00"))
        feed.analyze(dataplane_row("203.0.113.1", "2026-01-02 00:00:00"))

        for obs_class, value in ((ipv4.IPv4, "203.0.113.1"), (asn.ASN, "64500")):
            with self.subTest(observable=value):
                contexts = self.feed_contexts(obs_class, value, "DataplaneDNSRecursive")
                self.assertEqual(len(contexts), 1)
                self.assertEqual(contexts[0]["last_seen"], "2026-01-02T00:00:00")

    def test_dataplane_dnsrd_ips_in_one_as_keep_one_asn_context(self) -> None:
        """Tests that several IPs of one AS keep a single ASN context.

        Every row adds context to its AS, so while lastseen was compared a
        single run added one entry per IP to the AS document."""
        feed = dataplane_dnsrd.DataplaneDNSRecursive(
            **dataplane_dnsrd.DataplaneDNSRecursive._defaults.copy()
        )
        feed.analyze(dataplane_row("203.0.113.1", "2026-01-01 00:00:00"))
        feed.analyze(dataplane_row("203.0.113.2", "2026-01-02 00:00:00"))

        contexts = self.feed_contexts(asn.ASN, "64500", "DataplaneDNSRecursive")
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["name"], "EXAMPLE-AS")
        self.assertEqual(contexts[0]["last_seen"], "2026-01-02T00:00:00")

    def test_other_dataplane_feeds_keep_one_context(self) -> None:
        """Tests the same for the other Dataplane feeds with lastseen in their
        context. Their analyze() takes the same row."""
        feeds = [
            # Feed class, and the source of its IP context (None: the IP
            # context carries no timestamp).
            (dataplane_dnsrdany.DataplaneDNSAny, "DataplaneDNSAny"),
            (dataplane_dnsversion.DataplaneDNSVersion, None),
            (dataplane_sipinvite.DataplaneSIPInvite, "dataplane sip invite"),
            (dataplane_sipquery.DataplaneSIPQuery, "dataplane sip query"),
            (dataplane_smtpdata.DataplaneSMTPData, "DataplaneSMTPData"),
        ]
        for feed_class, ip_source in feeds:
            feed = feed_class(**feed_class._defaults.copy())
            feed.analyze(dataplane_row("203.0.113.1", "2026-01-01 00:00:00"))
            feed.analyze(dataplane_row("203.0.113.1", "2026-01-02 00:00:00"))

            checks = [(asn.ASN, "64500", feed.name)]
            if ip_source:
                checks.append((ipv4.IPv4, "203.0.113.1", ip_source))
            for obs_class, value, source in checks:
                with self.subTest(feed=feed.name, observable=value):
                    contexts = self.feed_contexts(obs_class, value, source)
                    self.assertEqual(len(contexts), 1)
                    self.assertEqual(contexts[0]["last_seen"], "2026-01-02T00:00:00")

    def test_dataplane_proto41_same_ip_keeps_one_context(self) -> None:
        """Tests that DataplaneProto41 updates the IP context when only
        lastseen changes. firstseen is the IP's own first sighting, so it stays
        compared."""
        feed = dataplane_proto41.DataplaneProto41(
            **dataplane_proto41.DataplaneProto41._defaults.copy()
        )
        feed.analyze(
            dataplane_row(
                "203.0.113.1", "2026-01-01 00:00:00", firstseen="2025-12-01 00:00:00"
            )
        )
        feed.analyze(
            dataplane_row(
                "203.0.113.1", "2026-01-02 00:00:00", firstseen="2025-12-01 00:00:00"
            )
        )

        contexts = self.feed_contexts(ipv4.IPv4, "203.0.113.1", "DataplaneProto41")
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["firstseen"], "2025-12-01 00:00:00")
        self.assertEqual(contexts[0]["lastseen"], "2026-01-02T00:00:00")

    def test_dataplane_proto41_ips_in_one_as_keep_one_asn_context(self) -> None:
        """Tests that DataplaneProto41 keeps a single ASN context for several
        IPs of one AS.

        Its ASN context copies firstseen and lastseen from each IP's row, so
        both differ from row to row. The entry holds the last row's values."""
        feed = dataplane_proto41.DataplaneProto41(
            **dataplane_proto41.DataplaneProto41._defaults.copy()
        )
        feed.analyze(
            dataplane_row(
                "203.0.113.1", "2026-01-01 00:00:00", firstseen="2025-12-01 00:00:00"
            )
        )
        feed.analyze(
            dataplane_row(
                "203.0.113.2", "2026-01-02 00:00:00", firstseen="2025-12-02 00:00:00"
            )
        )

        contexts = self.feed_contexts(asn.ASN, "64500", "DataplaneProto41")
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["name"], "EXAMPLE-AS")
        self.assertEqual(contexts[0]["firstseen"], "2025-12-02 00:00:00")
        self.assertEqual(contexts[0]["lastseen"], "2026-01-02T00:00:00")

    def test_abuseipdb_keeps_one_context(self) -> None:
        """Tests that AbuseIPDB updates the IP context on the next run.

        date_added is now(), and run() has no time filter, so every download
        of the blocklist added an entry to every listed IP."""
        feed = abuseipdb.AbuseIPDB(**abuseipdb.AbuseIPDB._defaults.copy())
        with mock.patch.object(abuseipdb, "datetime") as mock_datetime:
            mock_datetime.now.side_effect = [DAY_1, DAY_2]
            feed.analyze("203.0.113.1")
            feed.analyze("203.0.113.1")

        contexts = self.feed_contexts(ipv4.IPv4, "203.0.113.1", "AbuseIPDB")
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["date_added"], "2026-01-02T00:00:00Z")

    def test_azorult_tracker_keeps_one_context_per_observable(self) -> None:
        """Tests that AzorultTracker updates the context of every observable a
        panel produces when the panel is processed again.

        The context holds date_added (now()) and is added to the hostname, IP,
        URL and ASN of the panel."""
        item = pd.Series(
            {
                "_id": "0123456789",
                "domain": "azorult.example.com",
                "ip": "203.0.113.1",
                "asn": "AS64500",
                "country_code": "ZZ",
                "panel_index": "http://azorult.example.com/panel/index.php",
                "panel_path": "/panel/index.php",
                "panel_version": "3.3",
                "status": "online",
                "feeder": None,
                "first_seen": pd.Timestamp("2025-12-01", tz="UTC"),
                "data": None,
            }
        )
        feed = azorult_tracker.AzorultTracker(
            **azorult_tracker.AzorultTracker._defaults.copy()
        )
        with mock.patch.object(azorult_tracker, "datetime") as mock_datetime:
            # analyze() calls now() twice, so set one value per run.
            mock_datetime.now.return_value = DAY_1
            feed.analyze(item)
            mock_datetime.now.return_value = DAY_2
            feed.analyze(item)

        for obs_class, value in (
            (hostname.Hostname, "azorult.example.com"),
            (ipv4.IPv4, "203.0.113.1"),
            (url.Url, "http://azorult.example.com/panel/index.php"),
            (asn.ASN, "AS64500"),
        ):
            with self.subTest(observable=value):
                contexts = self.feed_contexts(obs_class, value, "Azorult-Tracker")
                self.assertEqual(len(contexts), 1)
                self.assertEqual(contexts[0]["date_added"], "2026-01-02T00:00:00Z")

    def tor_relay(self, fingerprint: str, last_seen: str) -> dict:
        return {
            "nickname": "example",
            "fingerprint": fingerprint,
            "last_seen": last_seen,
            "flags": ["Exit", "Running"],
            "exit_addresses": ["203.0.113.1"],
            "verified_host_names": [],
        }

    def test_tor_exit_nodes_keeps_one_context(self) -> None:
        """Tests that TorExitNodes updates the exit IP's context when only the
        relay's last_seen changes.

        The feed fetches every running relay on every run, and last_seen moves
        between runs. This is the feed #1097 was about."""
        feed = tor_exit_nodes.TorExitNodes(
            **tor_exit_nodes.TorExitNodes._defaults.copy()
        )
        feed.analyze(self.tor_relay("A" * 40, "2026-01-01 00:00:00"))
        feed.analyze(self.tor_relay("A" * 40, "2026-01-02 00:00:00"))

        contexts = self.feed_contexts(ipv4.IPv4, "203.0.113.1", "TorExitNodes")
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["last_seen"], "2026-01-02 00:00:00")

    def test_tor_exit_nodes_different_relays_keep_their_contexts(self) -> None:
        """Tests that two relays sharing an exit address keep one entry each:
        only last_seen is left out of the comparison, not the relay's
        identity."""
        feed = tor_exit_nodes.TorExitNodes(
            **tor_exit_nodes.TorExitNodes._defaults.copy()
        )
        feed.analyze(self.tor_relay("A" * 40, "2026-01-01 00:00:00"))
        feed.analyze(self.tor_relay("B" * 40, "2026-01-01 00:00:00"))

        contexts = self.feed_contexts(ipv4.IPv4, "203.0.113.1", "TorExitNodes")
        self.assertEqual(
            sorted(context["fingerprint"] for context in contexts),
            ["A" * 40, "B" * 40],
        )

    def test_sslblacklist_ja3_keeps_one_context(self) -> None:
        """Tests that SSLBlacklistJA3 updates the JA3 context when only
        last_seen changes.

        run() keeps the rows whose last_seen is newer than the last run, so a
        fingerprint is processed again each time it is seen again. first_seen
        is a pandas Timestamp, so this also relies on add_context comparing
        the form the context is stored in."""
        feed = sslblacklist_ja3.SSLBlacklistJA3(
            **sslblacklist_ja3.SSLBlacklistJA3._defaults.copy()
        )
        for last_seen in ("2026-01-01 00:00:00", "2026-01-02 00:00:00"):
            feed.analyze(
                pd.Series(
                    {
                        "ja3_md5": "0123456789abcdef0123456789abcdef",
                        "first_seen": pd.Timestamp("2025-12-01 00:00:00"),
                        "last_seen": pd.Timestamp(last_seen),
                        "threat": "example",
                    }
                )
            )

        contexts = self.feed_contexts(
            ja3.JA3, "0123456789abcdef0123456789abcdef", "SSLBlacklistJA3"
        )
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["first_seen"], "2025-12-01T00:00:00")
        self.assertEqual(contexts[0]["last_seen"], "2026-01-02T00:00:00")

    def test_rulezsk_keeps_one_context(self) -> None:
        """Tests that RulezSKBruteforceBlocker updates the IP context when the
        IP is reported again.

        Its first_seen holds the row's last_report, and run() processes a row
        again whenever last_report moves past the last run; count can change
        with it. id is still compared."""
        feed = rulezskbruteforceblocker.RulezSKBruteforceBlocker(
            **rulezskbruteforceblocker.RulezSKBruteforceBlocker._defaults.copy()
        )
        for day, count in ((1, "1"), (2, "2")):
            feed.analyze(
                pd.Series(
                    {
                        "ip": "203.0.113.1",
                        "last_report": datetime.datetime(2026, 1, day),
                        "count": count,
                        "id": "100",
                    }
                )
            )

        contexts = self.feed_contexts(
            ipv4.IPv4, "203.0.113.1", "RulezSKBruteforceBlocker"
        )
        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["first_seen"], "2026-01-02T00:00:00")
        self.assertEqual(contexts[0]["count"], "2")
        self.assertEqual(contexts[0]["id"], "100")


if __name__ == "__main__":
    unittest.main()
