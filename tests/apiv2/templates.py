import datetime
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.template import Template
from core.web import webapp

client = TestClient(webapp.app)

class TemplateTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()
        self.template = Template(name="FakeTemplate", template="<BLAH>").save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_search_template(self):
        response = client.post("/api/v2/templates/search", json={"name": ""})
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['templates'][0]['name'], "FakeTemplate")
        self.assertEqual(data['total'], 1)

    def test_delete_template(self):
        response = client.delete(f"/api/v2/templates/{self.template.id}")
        self.assertEqual(response.status_code, 200, response.json())
        self.assertEqual(Template.get(self.template.id), None)

    def test_create_template(self):
        response = client.post(
            "/api/v2/templates",
            json={
                'template': {
                    "name": "FakeTemplate2",
                    "template": "<BLAH>"
                    }
            }
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['name'], "FakeTemplate2")
        self.assertEqual(data['template'], "<BLAH>")
        self.assertEqual(data['id'], Template.find(name="FakeTemplate2").id)

    def test_update_template(self):
        response = client.post(
            f"/api/v2/templates",
            json={
                'template': {
                    "id": self.template.id,
                    "name": "FakeTemplateFoo",
                    "template": "<FOO>"
                    }
            }
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data['name'], "FakeTemplateFoo")
        self.assertEqual(data['template'], "<FOO>")
        self.assertEqual(data['id'], self.template.id)
        db_template = Template.get(self.template.id)
        self.assertEqual(db_template.template, "<FOO>")
        self.assertEqual(db_template.name, "FakeTemplateFoo")
        self.assertEqual(db_template.id, data['id'])
