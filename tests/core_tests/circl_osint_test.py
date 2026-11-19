import datetime
import json
import unittest
from unittest import mock

from core import database_arango
from core.schemas import model, observable
from plugins.feeds.public import circl_osint

FIXTURES = "tests/misp_test_data/feed_osint"
UTC = datetime.timezone.utc
UNSUPERVISED = 'misp:automation-level="unsupervised"'
EVENT_UUID = "60118dab-1ab8-40b2-b02b-b6f80aba047c"


def load_fixture(name: str) -> dict:
    with open(f"{FIXTURES}/{name}", encoding="utf-8") as f:
        return json.load(f)


def manifest_entry(timestamp: datetime.datetime, tags: list[str] | None = None) -> dict:
    entry = {
        "Orgc": {"name": "CIRCL", "uuid": "55f6ea5e-2c60-40e5-964f-47a8950d210f"},
        "info": "test event",
        "date": timestamp.strftime("%Y-%m-%d"),
        "analysis": "2",
        "threat_level_id": "3",
        "timestamp": str(int(timestamp.timestamp())),
    }
    if tags is not None:
        entry["Tag"] = [
            {"name": name, "colour": "#ffffff", "local": False} for name in tags
        ]
    return entry


def day(n: int) -> datetime.datetime:
    return datetime.datetime(2026, 1, n, tzinfo=UTC)


class SelectEventsTest(unittest.TestCase):
    """select_events() picks the manifest entries a run should fetch."""

    def test_keeps_events_updated_since(self):
        manifest = {
            "new": manifest_entry(day(11), []),
            "old": manifest_entry(day(9), []),
        }
        self.assertEqual(circl_osint.select_events(manifest, day(10), set()), ["new"])

    def test_event_at_since_is_kept(self):
        manifest = {"exact": manifest_entry(day(10), [])}
        self.assertEqual(circl_osint.select_events(manifest, day(10), set()), ["exact"])

    def test_skip_tag_excludes_event(self):
        manifest = {
            "kept": manifest_entry(day(2), ["tlp:clear"]),
            "skipped": manifest_entry(day(3), ["tlp:clear", UNSUPERVISED]),
        }
        selected = circl_osint.select_events(manifest, day(1), {UNSUPERVISED})
        self.assertEqual(selected, ["kept"])

    def test_oldest_first(self):
        manifest = {
            "b": manifest_entry(day(3), []),
            "a": manifest_entry(day(2), []),
            "c": manifest_entry(day(4), []),
        }
        self.assertEqual(
            circl_osint.select_events(manifest, day(1), set()), ["a", "b", "c"]
        )

    def test_entry_without_tags(self):
        manifest = {"untagged": manifest_entry(day(2))}
        self.assertEqual(
            circl_osint.select_events(manifest, day(1), {"anything"}), ["untagged"]
        )

    def test_real_manifest_shape(self):
        """The trimmed copy of CIRCL's manifest: string timestamps, Tag lists."""
        manifest = load_fixture("manifest.json")
        since = datetime.datetime(2026, 8, 1, tzinfo=UTC)
        selected = circl_osint.select_events(manifest, since, {UNSUPERVISED})
        self.assertEqual(selected, [EVENT_UUID])


class EventAttributesTest(unittest.TestCase):
    """event_attributes() walks top-level and object attributes."""

    def test_top_level_attributes_have_no_parent(self):
        attribute = {"type": "ip-dst", "value": "198.51.100.1"}
        event = {"Attribute": [attribute]}
        self.assertEqual(list(circl_osint.event_attributes(event)), [(attribute, None)])

    def test_object_attributes_carry_their_object(self):
        attribute = {"type": "domain", "value": "a.example"}
        obj = {"name": "domain-ip", "Attribute": [attribute]}
        event = {"Object": [obj]}
        self.assertEqual(list(circl_osint.event_attributes(event)), [(attribute, obj)])

    def test_event_without_either_list(self):
        self.assertEqual(list(circl_osint.event_attributes({})), [])


class ParseAttributeTest(unittest.TestCase):
    """parse_attribute() maps one MISP attribute to a Yeti type and value."""

    def attribute(self, **overrides) -> dict:
        attribute = {
            "type": "ip-dst",
            "category": "Network activity",
            "value": "198.51.100.1",
            "to_ids": True,
            "deleted": False,
            "comment": "",
        }
        attribute.update(overrides)
        return attribute

    def test_maps_ip_dst_to_ipv4(self):
        parsed = circl_osint.parse_attribute(self.attribute())
        self.assertEqual((parsed.type, parsed.value), ("ipv4", "198.51.100.1"))

    def test_maps_domain_to_hostname(self):
        parsed = circl_osint.parse_attribute(
            self.attribute(type="domain", value="evil.example")
        )
        self.assertEqual((parsed.type, parsed.value), ("hostname", "evil.example"))

    def test_deleted_attribute_is_skipped(self):
        self.assertIsNone(circl_osint.parse_attribute(self.attribute(deleted=True)))

    def test_non_ids_attribute_is_skipped(self):
        self.assertIsNone(circl_osint.parse_attribute(self.attribute(to_ids=False)))

    def test_external_analysis_is_skipped(self):
        attribute = self.attribute(
            type="url", category="External analysis", value="https://blog.example/p"
        )
        self.assertIsNone(circl_osint.parse_attribute(attribute))

    def test_unmapped_type_is_skipped(self):
        self.assertIsNone(
            circl_osint.parse_attribute(self.attribute(type="text", value="hello"))
        )

    def test_composite_filename_hash_keeps_hash_and_filename(self):
        attribute = self.attribute(
            type="filename|sha256",
            category="Payload delivery",
            value="dropper.exe|" + "a" * 64,
        )
        parsed = circl_osint.parse_attribute(attribute)
        self.assertEqual((parsed.type, parsed.value), ("sha256", "a" * 64))
        self.assertEqual(parsed.context, {"filename": "dropper.exe"})

    def test_plain_attribute_has_empty_context(self):
        self.assertEqual(circl_osint.parse_attribute(self.attribute()).context, {})


class ExternalSourcesTest(unittest.TestCase):
    """external_sources() collects External analysis links for context."""

    def test_collects_urls_and_links_regardless_of_to_ids(self):
        def attribute(type_, category, to_ids, value):
            return {
                "type": type_,
                "category": category,
                "to_ids": to_ids,
                "value": value,
            }

        event = {
            "Attribute": [
                attribute("url", "External analysis", True, "https://a.example/1"),
                attribute("link", "External analysis", False, "https://b.example/2"),
                attribute("comment", "External analysis", False, "not a link"),
                attribute("url", "Network activity", True, "https://c2.example/"),
            ]
        }
        self.assertEqual(
            circl_osint.external_sources(event),
            ["https://a.example/1", "https://b.example/2"],
        )

    def test_event_without_attributes(self):
        self.assertEqual(circl_osint.external_sources({"Object": []}), [])


class AttributeContextTest(unittest.TestCase):
    """event_context() and attribute_context() build the context stored on
    each observable: the event part is computed once, the attribute part per
    attribute."""

    BASE = "https://www.circl.lu/doc/misp/feed-osint/"

    def setUp(self):
        self.event = load_fixture(f"{EVENT_UUID}.json")["Event"]
        self.applocktx = self.event["Attribute"][4]
        assert self.applocktx["value"] == "/tmp/.applocktx"

    def context(self, attribute: dict) -> dict:
        shared = circl_osint.event_context(self.event, self.BASE)
        return circl_osint.attribute_context(shared, attribute)

    def test_event_fields(self):
        context = self.context(self.applocktx)
        self.assertEqual(context["event_uuid"], EVENT_UUID)
        self.assertEqual(
            context["info"],
            "[CERT-FR] Sandworm intrusion set campaign targeting Centreon systems",
        )
        self.assertEqual(context["date"], "2021-01-27")
        self.assertEqual(context["org"], "CERT-FR_1510")
        self.assertEqual(context["category"], "Artifacts dropped")
        self.assertEqual(context["comment"], "Socket created by Exaramel")
        self.assertEqual(context["link"], f"{self.BASE}{EVENT_UUID}.json")

    def test_external_sources_joined(self):
        context = self.context(self.applocktx)
        self.assertEqual(
            context["external sources"],
            "https://wws.cert-ist.com/private/fr/IocAttack_details"
            "?format=html&objectType=ATK&ref=CERT-IST/ATK-2016-066",
        )

    def test_empty_comment_is_left_out(self):
        context = self.context(dict(self.applocktx, comment=""))
        self.assertNotIn("comment", context)


class AttributeTagsTest(unittest.TestCase):
    """attribute_tags() merges the event's tags with the attribute's own."""

    def test_event_and_attribute_tags(self):
        event = {"Tag": [{"name": "tlp:clear"}, {"name": "type:OSINT"}]}
        attribute = {"Tag": [{"name": 'osint:certainty="50"'}]}
        self.assertEqual(
            circl_osint.attribute_tags(event, attribute),
            ["tlp:clear", "type:OSINT", 'osint:certainty="50"'],
        )

    def test_no_tags(self):
        self.assertEqual(circl_osint.attribute_tags({}, {}), [])


def tiny_event(uuid: str, ip: str, tags: list[str] | None = None) -> dict:
    """A feed event file with one ip-dst attribute."""
    return {
        "Event": {
            "uuid": uuid,
            "info": f"event {uuid}",
            "date": "2026-01-01",
            "Orgc": {"name": "CIRCL"},
            "Tag": [{"name": name} for name in tags or []],
            "Attribute": [
                {
                    "type": "ip-dst",
                    "category": "Network activity",
                    "value": ip,
                    "to_ids": True,
                    "deleted": False,
                    "comment": "",
                }
            ],
        }
    }


def values_by_type() -> dict[str, set[str]]:
    observables, _ = observable.Observable.filter({"value": ""})
    by_type: dict[str, set[str]] = {}
    for obs in observables:
        by_type.setdefault(obs.type, set()).add(obs.value)
    return by_type


class CirclOsintFeedAnalyzeTest(unittest.TestCase):
    """analyze_event() stores one feed event's observables."""

    def setUp(self):
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.feed = circl_osint.CirclOsintFeed(**circl_osint.CirclOsintFeed._defaults)
        self.event = load_fixture(f"{EVENT_UUID}.json")["Event"]

    def test_fixture_event_observables(self):
        self.feed.analyze_event(self.event)
        by_type = values_by_type()
        self.assertEqual(
            by_type["file"],
            {
                "/tmp/.applocktx",
                "/tmp/.applock",
                "configtx.json",
                "centreon_module_linux_app64",
                "search.php",
            },
        )
        self.assertEqual(
            {t: len(v) for t, v in by_type.items()},
            {"file": 5, "sha256": 2, "sha1": 2, "md5": 2},
        )

    def test_event_and_attribute_tags_are_applied(self):
        self.feed.analyze_event(self.event)
        applocktx = observable.find(value="/tmp/.applocktx")
        assert applocktx is not None
        tags = {tag.name for tag in applocktx.tags}
        self.assertLessEqual({"circl-osint", "tlp:white", "type:osint"}, tags)
        filename = observable.find(value="centreon_module_linux_app64")
        assert filename is not None
        self.assertIn(
            model.normalize_name('cossi:fiabilite="Bonne"'),
            {tag.name for tag in filename.tags},
        )

    def test_context(self):
        self.feed.analyze_event(self.event)
        sha256 = observable.find(
            value="e1ff729f45b587a5ebbc8a8a97a7923fc4ada14de4973704c9b4b89c50fd1146"
        )
        assert sha256 is not None
        self.assertEqual(
            sha256.context,
            [
                {
                    "source": self.feed.name,
                    "event_uuid": EVENT_UUID,
                    "info": "[CERT-FR] Sandworm intrusion set campaign targeting Centreon systems",
                    "date": "2021-01-27",
                    "org": "CERT-FR_1510",
                    "link": f"https://www.circl.lu/doc/misp/feed-osint/{EVENT_UUID}.json",
                    "external sources": "https://wws.cert-ist.com/private/fr/IocAttack_details"
                    "?format=html&objectType=ATK&ref=CERT-IST/ATK-2016-066",
                    "category": "Payload delivery",
                }
            ],
        )
        applocktx = observable.find(value="/tmp/.applocktx")
        assert applocktx is not None
        self.assertEqual(applocktx.context[0]["comment"], "Socket created by Exaramel")

    def test_object_members_are_linked_to_the_first_member(self):
        self.feed.analyze_event(self.event)
        filename = observable.find(value="centreon_module_linux_app64")
        assert filename is not None
        vertices, _, _ = filename.neighbors(link_types=["linked_by_misp_file"])
        self.assertEqual(
            {vertex.value for vertex in vertices.values()},
            {
                "e1ff729f45b587a5ebbc8a8a97a7923fc4ada14de4973704c9b4b89c50fd1146",
                "a739f44390037b3d0a3942cd43d161a7c45fd7e7",
                "92ef0aaf5f622b1253e5763f11a08857",
            },
        )

    def test_rerun_keeps_one_context_per_event(self):
        self.feed.analyze_event(self.event)
        self.feed.analyze_event(self.event)
        applocktx = observable.find(value="/tmp/.applocktx")
        assert applocktx is not None
        self.assertEqual(len(applocktx.context), 1)

    def test_invalid_value_is_skipped(self):
        event = tiny_event("u1", "not-an-ip")["Event"]
        event["Attribute"].append(dict(event["Attribute"][0], value="198.51.100.7"))
        self.feed.analyze_event(event)
        self.assertEqual(values_by_type(), {"ipv4": {"198.51.100.7"}})

    def test_value_its_type_cannot_hold_is_skipped(self):
        """A regkey attribute maps to registry_key, whose model needs a key,
        data and a hive that a MISP attribute doesn't carry."""
        event = tiny_event("u1", "198.51.100.7")["Event"]
        event["Attribute"].append(
            dict(
                event["Attribute"][0],
                type="regkey",
                value=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            )
        )
        with self.assertLogs(level="WARNING") as logs:
            self.feed.analyze_event(event)
        self.assertEqual(values_by_type(), {"ipv4": {"198.51.100.7"}})
        self.assertIn("skipping invalid registry_key", logs.output[0])

    def test_tag_that_normalizes_to_nothing_is_ignored(self):
        event = tiny_event("u1", "198.51.100.8", tags=['""', "tlp:clear"])["Event"]
        self.feed.analyze_event(event)
        ip = observable.find(value="198.51.100.8")
        assert ip is not None
        self.assertEqual({tag.name for tag in ip.tags}, {"tlp:clear", "circl-osint"})


class CirclOsintFeedRunTest(unittest.TestCase):
    """run() fetches the manifest, then only the events a run needs."""

    BASE = "https://www.circl.lu/doc/misp/feed-osint/"

    def setUp(self):
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.feed = circl_osint.CirclOsintFeed(**circl_osint.CirclOsintFeed._defaults)
        self.now = datetime.datetime.now(UTC)
        self.files: dict[str, dict | Exception] = {}
        self.requested: list[str] = []

    def serve(self, url: str, **kwargs):
        self.requested.append(url)
        payload = self.files[url]
        if isinstance(payload, Exception):
            raise payload
        if payload is None:
            return None
        return mock.Mock(json=mock.Mock(return_value=payload))

    def run_feed(self, manifest: dict | None, events: dict[str, dict | Exception]):
        self.files = {f"{self.BASE}manifest.json": manifest}
        for uuid, payload in events.items():
            self.files[f"{self.BASE}{uuid}.json"] = payload
        with mock.patch.object(self.feed, "_make_request", side_effect=self.serve):
            self.feed.run()

    def ago(self, **kwargs) -> datetime.datetime:
        return self.now - datetime.timedelta(**kwargs)

    def test_first_run_fetches_the_history_window(self):
        manifest = {
            "recent": manifest_entry(self.ago(days=1), ["tlp:clear"]),
            "month": manifest_entry(self.ago(days=30), ["tlp:clear"]),
            "old": manifest_entry(self.ago(days=100), ["tlp:clear"]),
            "dump": manifest_entry(self.ago(days=2), ["tlp:clear", UNSUPERVISED]),
        }
        self.run_feed(
            manifest,
            {
                "recent": tiny_event("recent", "198.51.100.1"),
                "month": tiny_event("month", "198.51.100.2"),
                "old": tiny_event("old", "198.51.100.3"),
                "dump": tiny_event("dump", "198.51.100.4"),
            },
        )
        self.assertEqual(
            self.requested,
            [
                f"{self.BASE}manifest.json",
                f"{self.BASE}month.json",
                f"{self.BASE}recent.json",
            ],
        )
        self.assertEqual(values_by_type(), {"ipv4": {"198.51.100.1", "198.51.100.2"}})

    def test_unmodified_manifest_fetches_nothing(self):
        self.run_feed(None, {})
        self.assertEqual(self.requested, [f"{self.BASE}manifest.json"])
        self.assertEqual(values_by_type(), {})

    def test_failed_event_fetch_does_not_stop_the_run(self):
        manifest = {
            "broken": manifest_entry(self.ago(days=2), []),
            "fine": manifest_entry(self.ago(days=1), []),
        }
        self.run_feed(
            manifest,
            {
                "broken": RuntimeError("returned code: 404"),
                "fine": tiny_event("fine", "198.51.100.5"),
            },
        )
        self.assertEqual(values_by_type(), {"ipv4": {"198.51.100.5"}})

    def test_later_run_overlaps_the_last_run_by_a_day(self):
        self.feed.last_run = self.ago(days=10)
        manifest = {
            "inside_overlap": manifest_entry(self.ago(days=10, hours=12), []),
            "before_overlap": manifest_entry(self.ago(days=12), []),
        }
        self.run_feed(
            manifest,
            {
                "inside_overlap": tiny_event("inside_overlap", "198.51.100.6"),
                "before_overlap": tiny_event("before_overlap", "198.51.100.7"),
            },
        )
        self.assertEqual(values_by_type(), {"ipv4": {"198.51.100.6"}})


if __name__ == "__main__":
    unittest.main()
