from core import database_arango

from fastapi import FastAPI
from fastapi.testclient import TestClient
import unittest

from core.web import webapp

client = TestClient(webapp.app)

class ObservableTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_read_main(self):
        response = client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_get_observable(self):
        response = client.get("/api/v2/observables/")
        self.assertEqual(response.status_code, 200)

    def test_get_observable_key_value(self):
        response = client.get("/api/v2/observables/")
        self.assertEqual(response.status_code, 200)

    def test_create_observable(self):
        response = client.post(
            "/api/v2/observables/",
            json={"value": "toto.com", "type": "hostname"})
        data = response.json()
        self.assertIsNotNone(data['id'])
        self.assertEqual(response.status_code, 200)

        client.get(f"/api/v2/observables/{data['id']}")
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['value'], "toto.com")

    def test_update_observable(self):
        response = client.post(
            "/api/v2/observables/",
            json={"value": "toto.com", "type": "hostname"})
        data1 = response.json()
        self.assertIsNotNone(data1['id'])
        self.assertEqual(response.status_code, 200)

        response = client.put(
            f"/api/v2/observables/{data1['id']}",
            json={"context": {"context1": "asd"}, "replace": True})
        self.assertEqual(response.status_code, 200)
        data2 = response.json()
        self.assertEqual(data2['context'], {"context1": "asd"})
        self.assertEqual(data1['created'], data2['created'])
        self.assertEqual(data1['id'], data2['id'])

    def test_add_text(self):
        TEST_CASES = [
            ("toto.com", "toto.com", "hostname"),
            ("127.0.0.1", "127.0.0.1", "ip"),
            ("http://google.com/", "http://google.com/", "url"),
            ("http://tomchop[.]me/", "http://tomchop.me/", "url"),
        ]

        for test_case, expected_response, expected_type in TEST_CASES:
            response = client.post(
                "/api/v2/observables/add_text",
                json={"text": test_case})
            data = response.json()
            self.assertEqual(response.status_code, 200)
            self.assertIsNotNone(data['id'])
            self.assertEqual(data['value'], expected_response)
            self.assertEqual(data['type'], expected_type)

    def test_add_text_invalid(self):
        response = client.post(
            "/api/v2/observables/add_text",
            json={"text": "--toto"})
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['detail'], "Invalid observable '--toto'")
