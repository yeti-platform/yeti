import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.observables import hostname
from core.web import webapp

client = TestClient(webapp.app)


class ObservableTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.clear()

    def test_get_observable(self):
        obs = hostname.Hostname(value="tomchop.me").save()
        obs.tag(["tag1"])
        response = client.get(f"/api/v2/observables/{obs.id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["value"], "tomchop.me")
        self.assertIn("tag1", data["tags"])

    def test_observable_search(self):
        hostname.Hostname(value="tomchop.me").save()
        hostname.Hostname(value="tomchop2.com").save()
        # Test that we get all domain names that have toto in them
        response = client.post(
            "/api/v2/observables/search", json={"query": {"value": "tomch"}, "page": 0, "count": 10}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 2)

    def test_observable_search_tags_nonexist(self):
        obs1 = hostname.Hostname(value="tomchop.me").save()
        obs2 = hostname.Hostname(value="tomchop2.com").save()
        obs1.tag(["tag1"])
        obs2.tag(["tag2"])

        response = client.post(
            "/api/v2/observables/search",
            json={
                "query": {"tags": ["nonexist"]},
                "page": 0,
                "count": 10
            }
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data['observables']), 0)
        self.assertEqual(data['total'], 0)

    def test_observable_search_tags_exist(self):
        obs1 = hostname.Hostname(value="tomchop.me").save()
        obs2 = hostname.Hostname(value="tomchop2.com").save()
        obs1.tag(["tag1"])
        obs2.tag(["tag2"])
        response = client.post(
            "/api/v2/observables/search",
            json={
                "query": {"tags": ["tag1"]},
                "page": 0,
                "count": 10
            }
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data['observables']), 1)
        self.assertEqual(data['observables'][0]['value'], 'tomchop.me')
        self.assertEqual(data['total'], 1)

    def test_observable_search_returns_tags(self):
        response = client.post(
            "/api/v2/observables/",
            json={"value": "toto.com", "type": "hostname", "tags": ["tag1", "tag2"]},
        )
        self.assertEqual(response.status_code, 200)

        response = client.post(
            "/api/v2/observables/search", json={"query": {"value": "toto"}, "page": 0, "count": 10}
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data["observables"]), 1)
        self.assertEqual(data["total"], 1)
        self.assertIn("tag1", data["observables"][0]["tags"])
        self.assertIn("tag2", data["observables"][0]["tags"])

    def test_create_observable(self):
        response = client.post(
            "/api/v2/observables/",
            json={"value": "toto.com", "type": "hostname", "tags": ["tag1", "tag2"]},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(data["id"])
        self.assertEqual(data["value"], "toto.com")
        self.assertEqual(data["type"], "hostname")
        self.assertIn("tag1", data["tags"])
        self.assertIn("tag2", data["tags"])
        self.assertEqual(data["tags"]["tag1"]["fresh"], True)
        self.assertEqual(data["tags"]["tag2"]["fresh"], True)

        client.get(f"/api/v2/observables/{data['id']}")
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["value"], "toto.com")
        self.assertIn("tag1", data["tags"])
        self.assertIn("tag2", data["tags"])

    def test_bulk_add(self):
        request = {
            "observables": [
                {"value": "toto.com", "type": "hostname"},
                {"value": "toto2.com", "type": "hostname", "tags": ["tag1"]},
                {"value": "toto3.com", "type": "guess", "tags": ["tag1", "tag2"]},
            ]
        }
        response = client.post("/api/v2/observables/bulk", json=request)
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data), 3)
        self.assertEqual(data[0]["value"], "toto.com")
        self.assertEqual(len(data[0]["tags"]), 0)
        self.assertEqual(data[1]["value"], "toto2.com")
        self.assertEqual(len(data[1]["tags"]), 1)
        self.assertEqual(data[2]["value"], "toto3.com")
        self.assertEqual(data[2]["type"], "hostname")
        self.assertEqual(len(data[2]["tags"]), 2)

    def test_add_text(self):
        TEST_CASES = [
            ("toto.com", "toto.com", "hostname"),
            ("127.0.0.1", "127.0.0.1", "ipv4"),
            ("http://google.com/", "http://google.com/", "url"),
            ("http://tomchop[.]me/", "http://tomchop.me/", "url"),
        ]

        for test_case, expected_response, expected_type in TEST_CASES:
            response = client.post(
                "/api/v2/observables/add_text", json={"text": test_case}
            )
            data = response.json()
            self.assertEqual(response.status_code, 200)
            self.assertIsNotNone(data["id"])
            self.assertEqual(data["value"], expected_response)
            self.assertEqual(data["type"], expected_type)

    def test_add_text_invalid(self):
        response = client.post("/api/v2/observables/add_text", json={"text": "--toto"})
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data["detail"], "Invalid observable '--toto'")

    def test_add_text_tags(self):
        response = client.post(
            "/api/v2/observables/add_text",
            json={"text": "toto.com", "tags": ["tag1", "tag2"]},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("tag1", data["tags"])
        self.assertIn("tag2", data["tags"])
        self.assertEqual(data["tags"]["tag1"]["fresh"], True)
        self.assertEqual(data["tags"]["tag2"]["fresh"], True)

    def test_tag_observable(self):
        response = client.post(
            "/api/v2/observables/", json={"value": "toto.com", "type": "hostname"}
        )
        data = response.json()
        self.assertIsNotNone(data["id"])
        self.assertEqual(response.status_code, 200)
        observable_id = data["id"]

        response = client.post(
            f"/api/v2/observables/tag",
            json={"ids": [observable_id], "tags": ["tag1", "tag2"]},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["tagged"], 1, data)
        tag_relationships = data["tags"][f'observables/{observable_id}']
        self.assertEqual(len(tag_relationships), 2, data)
        self.assertIn("tag1", tag_relationships)
        self.assertEqual(tag_relationships["tag1"]["source"], f'observables/{observable_id}')
        self.assertIn("tag2", tag_relationships)
        self.assertEqual(tag_relationships["tag2"]["source"], f'observables/{observable_id}')

        response = client.post(
            f"/api/v2/tags/search", json={"name": "tag1", "count": 1, "page": 0}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["tags"]), 1)
        self.assertEqual(data["total"], 1)


class ObservableContextTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.clear()
        self.observable = hostname.Hostname(value="tomchop.me").save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_add_context(self) -> None:
        response = client.post(
            f"/api/v2/observables/{self.observable.id}/context",
            json={"context": {"key": "value"}, "source": "test_source"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["context"], [{"key": "value", "source": "test_source"}])

    def test_delete_context(self) -> None:
        response = client.post(
            f"/api/v2/observables/{self.observable.id}/context",
            json={"context": {"key": "value"}, "source": "test_source"},
        )
        self.assertEqual(response.status_code, 200)
        response = client.post(
            f"/api/v2/observables/{self.observable.id}/context/delete",
            json={"context": {"key": "value"}, "source": "test_source"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["context"], [])


if __name__ == "__main__":
    unittest.main()
