import datetime
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.template import Template
from core.schemas.observable import Observable
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

    def test_render_raw_template_by_id(self):
        Observable(value="1.1.1.1", type='ip').save()
        Observable(value="2.2.2.2", type='ip').save()
        Observable(value="3.3.3.3", type='ip').save()
        response = client.post(
            f"/api/v2/templates/render",
            json={
                'template_id': self.template.id,
                'observable_ids': [o.id for o in Observable.list()]
            }
        )
        data = response.text
        response.headers['Content-Disposition'] = 'attachment; filename=FakeTemplate.txt'
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data, "1.1.1.1\n2.2.2.2\n3.3.3.3\n")

    def test_render_raw_template_by_search(self):
        Observable(value="yeti1.com", type='hostname').save()
        Observable(value="yeti2.com", type='hostname').save()
        Observable(value="yeti3.com", type='hostname').save()
        Observable(value="hacker.com", type='hostname').save()
        response = client.post(
            f"/api/v2/templates/render",
            json={
                'template_id': self.template.id,
                'search_query': 'yeti'
            }
        )
        data = response.text
        response.headers['Content-Disposition'] = 'attachment; filename=FakeTemplate.txt'
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data, "yeti1.com\nyeti2.com\nyeti3.com\n")
