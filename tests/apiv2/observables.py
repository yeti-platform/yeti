import logging
import sys
import unittest

from core import database_arango
from core.schemas.observables import file, hostname
from core.schemas.user import UserSensitive
from core.web import webapp
from fastapi.testclient import TestClient

client = TestClient(webapp.app)


class ObservableTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        user = UserSensitive(username="test", password="test", enabled=True).save()
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user.api_key}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

    def test_get_observable(self):
        obs = file.File(
            value="empty",
            name="empty",
            size=0,
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            mime_type="inode/x-empty; charset=binary",
        ).save()
        obs.tag(["tag1"])
        response = client.get(f"/api/v2/observables/{obs.id}")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["name"], "empty")
        self.assertEqual(data["type"], "file")
        self.assertEqual(data["size"], 0)
        self.assertEqual(
            data["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(data["sha1"], "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(data["md5"], "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(data["mime_type"], "inode/x-empty; charset=binary")
        self.assertIn("tag1", data["tags"])

    def test_post_existing_observable(self):
        obs = hostname.Hostname(value="tomchop.me").save()
        obs.tag(["tag1"])
        response = client.post(
            "/api/v2/observables/",
            json={"value": "tomchop.me", "type": "hostname", "tags": []},
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(
            data["detail"], "Observable with value tomchop.me already exists"
        )

    def test_post_file_observable(self):
        response = client.post(
            "/api/v2/observables/",
            json={"value": "test_file", "type": "file", "tags": []},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["value"], "test_file")
        self.assertEqual(data["type"], "file")
        self.assertEqual(data["name"], None)
        self.assertEqual(data["size"], None)
        self.assertEqual(data["sha256"], None)
        self.assertEqual(data["sha1"], None)
        self.assertEqual(data["md5"], None)
        self.assertEqual(data["mime_type"], None)

    def test_patch_observable(self):
        obs = hostname.Hostname(value="tomchop.me").save()
        obs.tag(["tag1"])
        response = client.patch(
            f"/api/v2/observables/{obs.id}",
            json={"observable": {"value": "tomchop.com", "type": "hostname"}},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["value"], "tomchop.com")
        self.assertEqual(data["type"], "hostname")
        self.assertIn("tag1", data["tags"])

    def test_observable_search(self):
        hostname.Hostname(value="tomchop.me").save()
        hostname.Hostname(value="tomchop2.com").save()
        # Test that we get all domain names that have toto in them
        response = client.post(
            "/api/v2/observables/search",
            json={"query": {"value": "tomch"}, "page": 0, "count": 10},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data), 2)

    def test_observable_search_extended_response(self):
        file.File(
            value="empty",
            name="empty",
            size=0,
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            mime_type="inode/x-empty; charset=binary",
        ).save()
        response = client.post(
            "/api/v2/observables/search",
            json={"query": {"value": "empty"}, "page": 0, "count": 10},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["observables"]), 1)
        observable = data["observables"][0]
        self.assertEqual(observable["name"], "empty")
        self.assertEqual(observable["type"], "file")
        self.assertEqual(observable["size"], 0)
        self.assertEqual(
            observable["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(observable["sha1"], "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(observable["md5"], "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(observable["mime_type"], "inode/x-empty; charset=binary")

    def test_observable_search_tags_nonexist(self):
        obs1 = hostname.Hostname(value="tomchop.me").save()
        obs2 = hostname.Hostname(value="tomchop2.com").save()
        obs1.tag(["tag1"])
        obs2.tag(["tag2"])

        response = client.post(
            "/api/v2/observables/search",
            json={"query": {"tags": ["nonexist"]}, "page": 0, "count": 10},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data["observables"]), 0)
        self.assertEqual(data["total"], 0)

    def test_observable_search_tags_exist(self):
        obs1 = hostname.Hostname(value="tomchop.me").save()
        obs2 = hostname.Hostname(value="tomchop2.com").save()
        obs1.tag(["tag1"])
        obs2.tag(["tag2"])
        response = client.post(
            "/api/v2/observables/search",
            json={"query": {"tags": ["tag1"]}, "page": 0, "count": 10},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data["observables"]), 1)
        self.assertEqual(data["observables"][0]["value"], "tomchop.me")
        self.assertEqual(data["total"], 1)

    def test_observable_search_returns_tags(self):
        response = client.post(
            "/api/v2/observables/",
            json={"value": "toto.com", "type": "hostname", "tags": ["tag1", "tag2"]},
        )
        self.assertEqual(response.status_code, 200)
        response = client.post(
            "/api/v2/observables/search",
            json={"query": {"value": "toto"}, "page": 0, "count": 10},
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

    def test_create_observable_empty_tags(self):
        response = client.post(
            "/api/v2/observables/",
            json={"value": "toto.com", "type": "hostname", "tags": [""]},
        )
        data = response.json()
        self.assertEqual(response.status_code, 422, data)
        self.assertEqual(
            data["detail"][0]["msg"], "Value error, Tags cannot be empty", data
        )

    def test_create_extended_observable(self):
        response = client.post(
            "/api/v2/observables/extended",
            json={
                "observable": {
                    "value": "empty",
                    "name": "empty",
                    "size": 0,
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "mime_type": "inode/x-empty; charset=binary",
                    "type": "file",
                },
                "tags": ["tag1", "tag2"],
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(data["id"])
        self.assertEqual(data["name"], "empty")
        self.assertEqual(data["type"], "file")
        self.assertEqual(data["size"], 0)
        self.assertEqual(
            data["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(data["sha1"], "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(data["md5"], "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(data["mime_type"], "inode/x-empty; charset=binary")
        self.assertIn("tag1", data["tags"])
        self.assertIn("tag2", data["tags"])
        self.assertEqual(data["tags"]["tag1"]["fresh"], True)
        self.assertEqual(data["tags"]["tag2"]["fresh"], True)

    def test_bulk_add(self):
        request = {
            "observables": [
                {"value": "toto.com", "type": "hostname"},
                {"value": "toto2.com", "type": "hostname", "tags": ["tag1"]},
                {"value": "toto3.com", "type": "guess", "tags": ["tag1", "tag2"]},
                {"value": "blablabla", "type": "guess"},
            ]
        }
        response = client.post("/api/v2/observables/bulk", json=request)
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(data["added"]), 3)
        self.assertEqual(len(data["failed"]), 1)

        added = data["added"]
        self.assertEqual(added[0]["value"], "toto.com")
        self.assertEqual(len(added[0]["tags"]), 0)
        self.assertEqual(added[1]["value"], "toto2.com")
        self.assertEqual(len(added[1]["tags"]), 1)
        self.assertEqual(added[2]["value"], "toto3.com")
        self.assertEqual(added[2]["type"], "hostname")
        self.assertEqual(len(added[2]["tags"]), 2)

        self.assertEqual(data["failed"][0], "blablabla")

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
        self.assertEqual(data["detail"], "Invalid type for observable '--toto'")

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
            "/api/v2/observables/tag",
            json={"ids": [observable_id], "tags": ["tag1", "tag2"]},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["tagged"], 1, data)
        tag_relationships = data["tags"][f"observables/{observable_id}"]
        self.assertEqual(len(tag_relationships), 2, data)
        self.assertIn("tag1", tag_relationships)
        self.assertEqual(
            tag_relationships["tag1"]["source"], f"observables/{observable_id}"
        )
        self.assertIn("tag2", tag_relationships)
        self.assertEqual(
            tag_relationships["tag2"]["source"], f"observables/{observable_id}"
        )

        response = client.post(
            "/api/v2/tags/search", json={"name": "tag1", "count": 1, "page": 0}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["tags"]), 1)
        self.assertEqual(data["total"], 1)


class ObservableContextTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        user = UserSensitive(username="test", password="test", enabled=True).save()
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user.api_key}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}
        self.observable = hostname.Hostname(value="tomchop.me").save()
        self.observable2 = hostname.Hostname(value="tomchop2.me").save()
        self.observable2.add_context(
            "tests:ObservableContextTest", {"context_key": "context_value"}
        )

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

    def test_sarch_context(self) -> None:
        """Tests that we can filter observables based on context subfields."""
        response = client.post(
            "/api/v2/observables/search",
            json={"query": {"context.source": "tests:"}, "page": 0, "count": 10},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data["observables"]), 1)
        self.assertEqual(data["observables"][0]["value"], "tomchop2.me")

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
