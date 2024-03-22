import logging
import sys
import unittest

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
        self.template = Template(name="FakeTemplate", template=TEST_TEMPLATE).save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_search_template(self):
        response = client.post("/api/v2/templates/search", json={"query": {"name": ""}})
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["templates"][0]["name"], "FakeTemplate")
        self.assertEqual(data["total"], 1)

    def test_delete_template(self):
        response = client.delete(f"/api/v2/templates/{self.template.id}")
        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(Template.get(self.template.id), None)

    def test_create_template(self):
        response = client.post(
            "/api/v2/templates/",
            json={"template": {"name": "FakeTemplate2", "template": "<BLAH>"}},
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["name"], "FakeTemplate2")
        self.assertEqual(data["template"], "<BLAH>")
        self.assertEqual(data["id"], Template.find(name="FakeTemplate2").id)

    def test_update_template(self):
        response = client.patch(
            f"/api/v2/templates/{self.template.id}",
            json={
                "template": {
                    "name": "FakeTemplateFoo",
                    "template": "<FOO>",
                }
            },
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["name"], "FakeTemplateFoo")
        self.assertEqual(data["template"], "<FOO>")
        self.assertEqual(data["id"], self.template.id)
        db_template = Template.get(self.template.id)
        self.assertEqual(db_template.template, "<FOO>")
        self.assertEqual(db_template.name, "FakeTemplateFoo")
        self.assertEqual(db_template.id, data["id"])

    def test_render_template_by_id(self):
        ipv4.IPv4(value="1.1.1.1").save()
        ipv4.IPv4(value="2.2.2.2").save()
        ipv4.IPv4(value="3.3.3.3").save()
        response = client.post(
            "/api/v2/templates/render",
            json={
                "template_id": self.template.id,
                "observable_ids": [o.id for o in Observable.list()],
            },
        )
        data = response.text
        response.headers["Content-Disposition"] = (
            "attachment; filename=FakeTemplate.txt"
        )
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data, "<blah>\n1.1.1.1\n2.2.2.2\n3.3.3.3\n\n</blah>\n")

    def test_render_template_by_search(self):
        hostname.Hostname(value="yeti1.com").save()
        hostname.Hostname(value="yeti2.com").save()
        hostname.Hostname(value="yeti3.com").save()
        hostname.Hostname(value="hacker.com").save()
        response = client.post(
            "/api/v2/templates/render",
            json={"template_id": self.template.id, "search_query": "yeti"},
        )
        data = response.text
        response.headers["Content-Disposition"] = (
            "attachment; filename=FakeTemplate.txt"
        )
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data, "<blah>\nyeti1.com\nyeti2.com\nyeti3.com\n\n</blah>\n")
