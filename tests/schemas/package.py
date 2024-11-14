import datetime
import unittest

from pydantic import ValidationError

from core import database_arango
from core.schemas import entity, indicator, observable, package
from core.schemas.observables import hostname, ipv4


class YetiPackageTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

    def test_package_creation_from_methods(self) -> None:
        yeti_package = package.YetiPackage(
            timestamp="2024-04-10T10:00:00Z", source="SecretSource"
        )
        yeti_package.add_observable("toto.com", "hostname")
        yeti_package.add_observable("192.168.1.1", "ipv4")
        yeti_package.add_entity("Fresh campaign", "campaign")
        yeti_package.add_indicator(
            "awesome_regexp", "regex", pattern=".*", diamond="adversary"
        )
        yeti_package.add_relationship("Fresh campaign", "toto.com", "contacts")
        yeti_package.add_relationship(
            "Fresh campaign", "192.168.1.1", "communicates_with"
        )
        yeti_package.save()

        obs1 = observable.Observable.find(value="toto.com", type="hostname")
        obs2 = observable.Observable.find(value="192.168.1.1", type="ipv4")
        campaign = entity.Entity.find(name="Fresh campaign", type="campaign")
        regex = indicator.Indicator.find(name="awesome_regexp", type="regex")

        self.assertIsNotNone(obs1)
        self.assertIsNotNone(obs2)
        self.assertIsNotNone(campaign)
        self.assertIsNotNone(regex)

        vertices, paths, count = campaign.neighbors()

        self.assertEqual(len(paths), 2)
        self.assertEqual(count, 2)
        self.assertEqual(len(vertices), 2)

        for path in paths:
            if path[0].target == obs1.extended_id:
                self.assertEqual(path[0].source, campaign.extended_id)
                self.assertEqual(path[0].description, "")
                self.assertEqual(path[0].type, "contacts")
            elif path[0].target == obs2.extended_id:
                self.assertEqual(path[0].source, campaign.extended_id)
                self.assertEqual(path[0].description, "")
                self.assertEqual(path[0].type, "communicates_with")

        self.assertIn(obs1.extended_id, vertices)
        neighbor = vertices[obs1.extended_id]
        self.assertEqual(neighbor.id, obs1.id)
        self.assertIn(obs2.extended_id, vertices)
        neighbor = vertices[obs2.extended_id]
        self.assertEqual(neighbor.id, obs2.id)

    def test_package_creation_from_dict_objects(self) -> None:
        observables = [
            {"value": "toto.com", "type": "hostname"},
            {"value": "192.168.1.1", "type": "ipv4"},
        ]
        entities = [{"name": "Fresh campaign", "type": "campaign"}]
        indicators = [
            {
                "name": "awesome_regexp",
                "type": "regex",
                "pattern": ".*",
                "diamond": "adversary",
            }
        ]
        relationships = {
            "Fresh campaign": [
                {"target": "toto.com", "link_type": "contacts"},
                {"target": "192.168.1.1", "link_type": "communicates_with"},
            ]
        }

        yeti_package = package.YetiPackage(
            timestamp="2024-04-10T10:00:00Z",
            source="SecretSource",
            observables=observables,
            entities=entities,
            indicators=indicators,
            relationships=relationships,
        )
        yeti_package.save()

        obs1 = observable.Observable.find(value="toto.com", type="hostname")
        obs2 = observable.Observable.find(value="192.168.1.1", type="ipv4")
        campaign = entity.Entity.find(name="Fresh campaign", type="campaign")
        regex = indicator.Indicator.find(name="awesome_regexp", type="regex")

        self.assertIsNotNone(obs1)
        self.assertIsNotNone(obs2)
        self.assertIsNotNone(campaign)
        self.assertIsNotNone(regex)

        vertices, paths, count = campaign.neighbors()

        self.assertEqual(len(paths), 2)
        self.assertEqual(count, 2)
        self.assertEqual(len(vertices), 2)

        for path in paths:
            if path[0].target == obs1.extended_id:
                self.assertEqual(path[0].source, campaign.extended_id)
                self.assertEqual(path[0].description, "")
                self.assertEqual(path[0].type, "contacts")
            elif path[0].target == obs2.extended_id:
                self.assertEqual(path[0].source, campaign.extended_id)
                self.assertEqual(path[0].description, "")
                self.assertEqual(path[0].type, "communicates_with")

        self.assertIn(obs1.extended_id, vertices)
        neighbor = vertices[obs1.extended_id]
        self.assertEqual(neighbor.id, obs1.id)
        self.assertIn(obs2.extended_id, vertices)
        neighbor = vertices[obs2.extended_id]
        self.assertEqual(neighbor.id, obs2.id)

    def test_package_creation_from_objects(self) -> None:
        obs1 = hostname.Hostname(value="toto.com")
        obs2 = ipv4.IPv4(value="192.168.1.1")
        campaign = entity.Campaign(name="Fresh campaign")
        regex = indicator.Regex(
            name="awesome_regexp", pattern=".*", diamond="adversary"
        )
        relationships = {
            "Fresh campaign": [
                package.YetiPackageRelationship(
                    target=obs1.value, link_type="contacts"
                ),
                package.YetiPackageRelationship(
                    target=obs2.value, link_type="communicates_with"
                ),
            ]
        }
        yeti_package = package.YetiPackage(
            timestamp="2024-04-10T10:00:00Z",
            source="SecretSource",
            observables=[obs1, obs2],
            entities=[campaign],
            indicators=[regex],
            relationships=relationships,
        )
        yeti_package.save()
        obs1 = observable.Observable.find(value="toto.com", type="hostname")
        obs2 = observable.Observable.find(value="192.168.1.1", type="ipv4")
        campaign = entity.Entity.find(name="Fresh campaign", type="campaign")
        regex = indicator.Indicator.find(name="awesome_regexp", type="regex")

        self.assertIsNotNone(obs1)
        self.assertIsNotNone(obs2)
        self.assertIsNotNone(campaign)
        self.assertIsNotNone(regex)

        vertices, paths, count = campaign.neighbors()

        self.assertEqual(len(paths), 2)
        self.assertEqual(count, 2)
        self.assertEqual(len(vertices), 2)

        for path in paths:
            if path[0].target == obs1.extended_id:
                self.assertEqual(path[0].source, campaign.extended_id)
                self.assertEqual(path[0].description, "")
                self.assertEqual(path[0].type, "contacts")
            elif path[0].target == obs2.extended_id:
                self.assertEqual(path[0].source, campaign.extended_id)
                self.assertEqual(path[0].description, "")
                self.assertEqual(path[0].type, "communicates_with")

        self.assertIn(obs1.extended_id, vertices)
        neighbor = vertices[obs1.extended_id]
        self.assertEqual(neighbor.id, obs1.id)
        self.assertIn(obs2.extended_id, vertices)
        neighbor = vertices[obs2.extended_id]
        self.assertEqual(neighbor.id, obs2.id)

        yeti_package.save()

    def test_package_creation_from_json_string(self) -> None:
        json_string = """
        {"timestamp": "2024-04-10T10:00:00Z",
        "source": "SuperSecretSource",
        "tags": {},
        "observables": [
           {"value": "192.168.1.1", "type": "ipv4"},
           {"value": "toto.com", "type": "hostname"}
        ],
        "entities": [{"type": "campaign", "name": "Fresh campaign"}],
        "indicators": [{"type": "regex", "name": "awesome_regexp", "pattern": ".*", "diamond": "adversary"}],
        "relationships": {
           "Fresh campaign": [
              {"target": "192.168.1.1", "link_type": "communicates_with"},
              {"target": "toto.com", "link_type": "contacts"}
            ]
          }
        }
        """
        yeti_package = package.YetiPackage.from_json(json_string)
        yeti_package.save()

        obs1 = observable.Observable.find(value="toto.com", type="hostname")
        obs2 = observable.Observable.find(value="192.168.1.1", type="ipv4")
        campaign = entity.Entity.find(name="Fresh campaign", type="campaign")
        regex = indicator.Indicator.find(name="awesome_regexp", type="regex")

        self.assertIsNotNone(obs1)
        self.assertIsNotNone(obs2)
        self.assertIsNotNone(campaign)
        self.assertIsNotNone(regex)

        vertices, paths, count = campaign.neighbors()

        self.assertEqual(len(paths), 2)
        self.assertEqual(count, 2)
        self.assertEqual(len(vertices), 2)

        for path in paths:
            if path[0].target == obs1.extended_id:
                self.assertEqual(path[0].source, campaign.extended_id)
                self.assertEqual(path[0].description, "")
                self.assertEqual(path[0].type, "contacts")
            elif path[0].target == obs2.extended_id:
                self.assertEqual(path[0].source, campaign.extended_id)
                self.assertEqual(path[0].description, "")
                self.assertEqual(path[0].type, "communicates_with")

        self.assertIn(obs1.extended_id, vertices)
        neighbor = vertices[obs1.extended_id]
        self.assertEqual(neighbor.id, obs1.id)
        self.assertIn(obs2.extended_id, vertices)
        neighbor = vertices[obs2.extended_id]
        self.assertEqual(neighbor.id, obs2.id)

    def test_package_creation_timestamps(self) -> None:
        package.YetiPackage(timestamp="2024-04-10", source="SecretSource")
        package.YetiPackage(timestamp="2024-04-10T00:00:00", source="SecretSource")
        package.YetiPackage(timestamp="2024-04-10T10:00:00Z", source="SecretSource")
        package.YetiPackage(timestamp="2024-04-10T10:00:00.400+00:00", source="Secret")
        package.YetiPackage(
            timestamp=datetime.datetime(2024, 4, 10, 10, 0, 0), source="SecretSource"
        )
        package.YetiPackage(timestamp=1704067200, source="SecretSource")
        package.YetiPackage(timestamp=1704067200.0, source="SecretSource")

    def test_package_creation_bad_timestamps(self) -> None:
        with self.assertRaises(ValidationError):
            package.YetiPackage(timestamp="2024-04-10T10", source="SecretSource")
        with self.assertRaises(ValidationError):
            package.YetiPackage(timestamp="10-04-2024", source="SecretSource")
        with self.assertRaises(ValidationError):
            package.YetiPackage(timestamp=-99999999999999999, source="SecretSource")

    def test_generic_observable_creation(self) -> None:
        yeti_package = package.YetiPackage(
            timestamp="2024-04-10T10:00:00Z", source="SecretSource"
        )
        yeti_package.add_observable("new_observable_value", "new_observable_type")
        yeti_package.save()
        obs1 = observable.Observable.find(value="new_observable_value", type="generic")
        tags = obs1.get_tags()
        self.assertEqual("type:new_observable_type", tags[0][1].name)

    def test_package_creation_with_tags(self) -> None:
        tags = {
            "toto.com": ["tag1"],
            "Fresh campaign": ["tag2"],
            "global": ["tag3"],
        }

        yeti_package = package.YetiPackage(
            timestamp="2024-04-10T10:00:00Z", source="SecretSource", tags=tags
        )
        yeti_package.add_observable("toto.com", "hostname")
        yeti_package.add_entity("Fresh campaign", "campaign")
        yeti_package.save()
        obs1 = observable.Observable.find(value="toto.com", type="hostname")
        tags = obs1.get_tags()
        self.assertEqual(len(tags), 2)
        for tag in tags:
            self.assertIn(tag[1].name, ["tag1", "tag3"])

        campaign = entity.Entity.find(name="Fresh campaign", type="campaign")
        tags = campaign.get_tags()
        self.assertEqual(len(tags), 2)
        for tag in tags:
            self.assertIn(tag[1].name, ["tag2", "tag3"])

    def test_package_creation_from_json_with_tags(self) -> None:
        json_string = """
        {"timestamp": "2024-04-10T10:00:00Z",
        "source": "SuperSecretSource",
        "tags": {"toto.com": ["tag1"], "Fresh campaign": ["tag2"], "global": ["tag3"]},
        "observables": [
           {"value": "192.168.1.1", "type": "ipv4"},
           {"value": "toto.com", "type": "new_type"}
        ],
        "entities": [{"type": "campaign", "name": "Fresh campaign"}],
        "indicators": [{"type": "regex", "name": "awesome_regexp", "pattern": ".*", "diamond": "adversary"}],
        "relationships": {
           "Fresh campaign": [
              {"target": "192.168.1.1", "link_type": "communicates_with"},
              {"target": "toto.com", "link_type": "contacts"}
            ]
          }
        }
        """
        yeti_package = package.YetiPackage.from_json(json_string)
        yeti_package.save()

        obs1 = observable.Observable.find(value="192.168.1.1", type="ipv4")
        tags = obs1.get_tags()
        self.assertEqual(len(tags), 1)
        for tag in tags:
            self.assertEqual(tag[1].name, "tag3")

        obs2 = observable.Observable.find(value="toto.com", type="generic")
        tags = obs2.get_tags()
        self.assertEqual(len(tags), 3)
        for tag in tags:
            self.assertIn(tag[1].name, ["tag1", "type:new_type", "tag3"])

        campaign = entity.Entity.find(name="Fresh campaign", type="campaign")
        tags = campaign.get_tags()
        self.assertEqual(len(tags), 2)
        for tag in tags:
            self.assertIn(tag[1].name, ["tag2", "tag3"])

    def test_empty_package_creation(self) -> None:
        yeti_package = package.YetiPackage(
            timestamp="2024-04-10T10:00:00Z", source="SecretSource"
        )
        with self.assertRaises(ValueError):
            yeti_package.save()

    def test_package_creation_with_duplicate(self) -> None:
        yeti_package = package.YetiPackage(
            timestamp="2024-04-10T10:00:00Z", source="SecretSource"
        )
        yeti_package.add_observable("toto.com", "hostname")
        with self.assertRaises(ValueError):
            yeti_package.add_observable("toto.com", "hostname")

    def test_package_creation_with_missing_relationship_target(self) -> None:
        yeti_package = package.YetiPackage(
            timestamp="2024-04-10T10:00:00Z", source="SecretSource"
        )
        yeti_package.add_observable("toto.com", "hostname")
        yeti_package.add_relationship("toto.com", "192.168.1.1", "resolves")
        with self.assertRaises(ValueError):
            yeti_package.save()

    def test_package_creation_with_missing_relationship_source(self) -> None:
        yeti_package = package.YetiPackage(
            timestamp="2024-04-10T10:00:00Z", source="SecretSource"
        )
        yeti_package.add_observable("toto.com", "hostname")
        yeti_package.add_relationship("192.168.1.1", "toto.com", "resolves")
        with self.assertRaises(ValueError):
            yeti_package.save()

    def test_package_creation_with_small_source_string(self) -> None:
        with self.assertRaises(ValidationError):
            package.YetiPackage(timestamp="2024-04-10T10:00:00Z", source="a")
