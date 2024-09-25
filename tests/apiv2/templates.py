import json
import logging
import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.observable import Observable
from core.schemas.observables import hostname, ipv4
from core.schemas.template import Template
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)

TEST_TEMPLATE = """<blah>
{% for obs in data %}{{ obs.value }}
{% endfor %}
</blah>
"""


class TemplateTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        user = UserSensitive(username="test", password="test", enabled=True).save()
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user.api_key}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}
        temp_path = Path("/opt/yeti/templates")
        temp_path.mkdir(parents=True, exist_ok=True)
        self.temp_template_path = temp_path

        Template(name="FakeTemplate", template=TEST_TEMPLATE).save()
        for i in range(0, 100):
            Template(name=f"template_blah_{i:02}", template=f"fake_template_{i}").save()

    def tearDown(self) -> None:
        for file in Path(self.temp_template_path).rglob('*.jinja2'):
            file.unlink()
        database_arango.db.clear()

    def test_search_template(self):
        response = client.post("/api/v2/templates/search", json={'name': 'Fake'})
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["templates"][0]["name"], "FakeTemplate")
        self.assertEqual(data["total"], 1)

    def test_pagination(self):
        response = client.post("/api/v2/templates/search", json={"name": "blah"})
        data = response.json()

        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(len(data["templates"]), 50)
        self.assertEqual(data["templates"][0]["name"], "template_blah_00")
        self.assertEqual(data["templates"][49]["name"], "template_blah_49")
        self.assertEqual(data["total"], 100)

        response = client.post("/api/v2/templates/search", json={"name": "blah", 'page': 3, 'count': 5})
        data = response.json()
        self.assertEqual(len(data["templates"]), 5)
        self.assertEqual(data["templates"][0]["name"], "template_blah_15")
        self.assertEqual(data["templates"][4]["name"], "template_blah_19")

    def test_render_template_by_obs_ids(self):
        ipv4.IPv4(value="1.1.1.1").save()
        ipv4.IPv4(value="2.2.2.2").save()
        ipv4.IPv4(value="3.3.3.3").save()
        response = client.post(
            "/api/v2/templates/render",
            json={
                "template_name": "FakeTemplate",
                "observable_ids": [o.id for o in Observable.list()],
            },
        )
        data = response.text
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(response.headers['Content-Disposition'], "attachment; filename=FakeTemplate.txt")
        self.assertEqual(data, "<blah>\n1.1.1.1\n2.2.2.2\n3.3.3.3\n\n</blah>\n")

    def test_render_template_by_search(self):
        hostname.Hostname(value="yeti1.com").save()
        hostname.Hostname(value="yeti2.com").save()
        hostname.Hostname(value="yeti3.com").save()
        hostname.Hostname(value="hacker.com").save()
        response = client.post(
            "/api/v2/templates/render",
            json={"template_name": "FakeTemplate", "search_query": "yeti"},
        )
        data = response.text
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(response.headers['Content-Disposition'], "attachment; filename=FakeTemplate.txt")
        self.assertEqual(data, "<blah>\nyeti1.com\nyeti2.com\nyeti3.com\n\n</blah>\n")

    def test_render_nonexistent(self):
        response = client.post(
            "/api/v2/templates/render",
            json={"template_name": "NotExist", "search_query": "yeti"},
        )
        data = response.text
        self.assertEqual(response.status_code, 404, data)
        self.assertEqual(json.loads(data), {"detail": "Template NotExist not found."})
