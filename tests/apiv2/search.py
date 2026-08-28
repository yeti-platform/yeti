import logging
import sys
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas import dfiq, entity, indicator, observable, rbac, roles, user
from core.schemas.user import UserSensitive
from core.web import webapp
from core.web.apiv2.search import MAX_RESULTS_PER_TYPE

client = TestClient(webapp.app)


def sections_by_type(data: dict) -> dict[str, dict]:
    return {section["type"]: section for section in data["sections"]}


class searchTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

        user = UserSensitive(username="test", password="test", enabled=True).save()
        apikey = user.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": apikey}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

        entity.Malware(
            name="test_malware",
            description="Test malware entity",
            type="malware",
        ).save()
        m2 = entity.Malware(
            name="tagged_malware",
            description="malware entity 2",
            type="malware",
        ).save()
        m2.tag("tagged")
        m2.tag("global")

        r = indicator.Regex(
            name="test_regex_global",
            description="Test regex indicator",
            type="regex",
            pattern="^test.*",
            diamond="victim",
        ).save()
        o = observable.Hostname(
            description="Test hostname observable",
            type="hostname",
            value="test.tomchop.me",
        ).save()
        dfiq.DFIQScenario(
            name="test_dfiq",
            description="Test DFIQ",
            dfiq_tags=["tagged", "global"],
            dfiq_version="1.0.1",
            dfiq_yaml="name: test_dfiq\nversion: 1.0.1\ndescription: Test DFIQ",
        ).save()
        r.tag("tagged")
        o.tag(["tagged", "global"])

    def test_search_buckets_by_type(self) -> None:
        """A search term matches across types, each in its own section."""
        response = client.post("/api/v2/search", json={"query": "test"})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        sections = sections_by_type(data)
        self.assertCountEqual(
            sections.keys(), ["entity", "indicator", "dfiq", "observable"], data
        )
        self.assertEqual(sections["entity"]["total"], 1, data)
        self.assertEqual(sections["entity"]["results"][0]["name"], "test_malware")
        self.assertEqual(sections["indicator"]["total"], 1, data)
        self.assertEqual(
            sections["indicator"]["results"][0]["name"], "test_regex_global"
        )
        self.assertEqual(sections["dfiq"]["total"], 1, data)
        self.assertEqual(sections["dfiq"]["results"][0]["name"], "test_dfiq")
        self.assertEqual(sections["observable"]["total"], 1, data)
        self.assertEqual(
            sections["observable"]["results"][0]["value"], "test.tomchop.me"
        )

    def test_search_tag_substring_match(self) -> None:
        """Search matches tag names too, across every type that has that tag."""
        response = client.post("/api/v2/search", json={"query": "tagged"})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        sections = sections_by_type(data)
        self.assertEqual(sections["entity"]["total"], 1, data)
        self.assertEqual(sections["entity"]["results"][0]["name"], "tagged_malware")
        self.assertEqual(sections["indicator"]["total"], 1, data)
        self.assertEqual(sections["observable"]["total"], 1, data)

    def test_search_dfiq_tags_match(self) -> None:
        """Search matches dfiq_tags list entries."""
        response = client.post("/api/v2/search", json={"query": "global"})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        sections = sections_by_type(data)
        self.assertEqual(sections["dfiq"]["total"], 1, data)
        self.assertEqual(sections["dfiq"]["results"][0]["name"], "test_dfiq")
        # "global" also matches the tagged_malware/regex/hostname tag.
        self.assertEqual(sections["entity"]["total"], 1, data)
        self.assertEqual(sections["indicator"]["total"], 1, data)
        self.assertEqual(sections["observable"]["total"], 1, data)

    def test_search_no_results_for_type(self) -> None:
        """A type with no matches still gets a section, empty."""
        response = client.post("/api/v2/search", json={"query": "test_malware"})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        sections = sections_by_type(data)
        self.assertEqual(sections["entity"]["total"], 1, data)
        self.assertEqual(sections["indicator"]["total"], 0, data)
        self.assertEqual(sections["indicator"]["results"], [], data)
        self.assertEqual(sections["dfiq"]["total"], 0, data)
        self.assertEqual(sections["observable"]["total"], 0, data)

    def test_search_value_substring_does_not_crowd_out_other_types(self) -> None:
        """A high-volume substring match on observable `value` must not push
        matches from other types out of the response -- each type has its
        own bounded slice, so they can never compete for the same page.
        """
        # A handful of hash-like observables that all happen to contain
        # "fed" as a substring, the way a hex hash might.
        for i in range(5):
            observable.SHA256(value=f"fed{i:02x}" + "0" * 59).save()
        entity.Malware(name="federated_exfil_campaign", type="malware").save()

        response = client.post(
            "/api/v2/search", json={"query": "fed", "count_per_type": 1}
        )
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        sections = sections_by_type(data)

        # The entity match is present and correct, regardless of how many
        # observable hash matches exist.
        self.assertEqual(sections["entity"]["total"], 1, data)
        self.assertEqual(
            sections["entity"]["results"][0]["name"], "federated_exfil_campaign"
        )
        # Observable bucket independently reports its own total and is
        # capped by count_per_type, without affecting the entity bucket.
        self.assertEqual(sections["observable"]["total"], 5, data)
        self.assertEqual(len(sections["observable"]["results"]), 1, data)

    def test_search_count_per_type_limits_results(self) -> None:
        """count_per_type bounds each section independently."""
        for i in range(3):
            entity.Malware(name=f"limit_test_{i}", type="malware").save()

        response = client.post(
            "/api/v2/search", json={"query": "limit_test", "count_per_type": 2}
        )
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        sections = sections_by_type(data)
        self.assertEqual(sections["entity"]["total"], 3, data)
        self.assertEqual(len(sections["entity"]["results"]), 2, data)

    def test_search_rejects_count_per_type_outside_the_allowed_range(self) -> None:
        """A non-positive count_per_type used to be accepted and silently
        return no results, which reads as "nothing matched" rather than
        "your request was wrong"."""
        for count_per_type in (0, -1, MAX_RESULTS_PER_TYPE + 1):
            with self.subTest(count_per_type=count_per_type):
                response = client.post(
                    "/api/v2/search",
                    json={"query": "test", "count_per_type": count_per_type},
                )
                self.assertEqual(response.status_code, 422, response.text)

        for count_per_type in (1, MAX_RESULTS_PER_TYPE):
            with self.subTest(count_per_type=count_per_type):
                response = client.post(
                    "/api/v2/search",
                    json={"query": "test", "count_per_type": count_per_type},
                )
                self.assertEqual(response.status_code, 200, response.text)


class searchRbacTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        rbac.RBAC_ENABLED = True
        database_arango.RBAC_ENABLED = True

        self.entity_visible = entity.Malware(name="rbac_visible_malware").save()
        self.entity_hidden = entity.Malware(name="rbac_hidden_malware").save()

        self.user1 = user.UserSensitive(username="user1").save()
        self.user1.link_to_acl(self.entity_visible, roles.Role.READER)
        user1_apikey = self.user1.create_api_key("default")
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user1_apikey}
        ).json()
        self.user1_token = token_data["access_token"]

    def tearDown(self) -> None:
        rbac.RBAC_ENABLED = False
        database_arango.RBAC_ENABLED = False

    def test_search_respects_acls(self) -> None:
        """Grouped search only returns objects the user has ACL access to."""
        response = client.post(
            "/api/v2/search",
            json={"query": "rbac_"},
            headers={"Authorization": f"Bearer {self.user1_token}"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        sections = sections_by_type(data)
        self.assertEqual(sections["entity"]["total"], 1, data)
        self.assertEqual(
            sections["entity"]["results"][0]["name"], "rbac_visible_malware"
        )
