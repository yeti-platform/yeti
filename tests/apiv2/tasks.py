import datetime
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from core import database_arango, taskmanager
from core.schemas.observable import Observable
from core.schemas.task import ExportTask, FeedTask
from core.schemas.template import Template
from core.web import webapp

client = TestClient(webapp.app)

class FakeTask(FeedTask):
    _DATA = ['asd1.com', 'asd2.com', 'asd3.com']
    _defaults = {
        "frequency": datetime.timedelta(hours=1),
        "type": "feed",
        "description": "Dummy feed",
    }

    def run(self):
        pass

class TaskTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()
        taskmanager.TaskManager.register_task(FakeTask)

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_search_tasks(self):
        response = client.post("/api/v2/tasks/search", json={"name": "FakeTask"})
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['tasks'][0]['name'], "FakeTask")
        self.assertEqual(data['total'], 1)

    def test_toggle_task(self):
        response = client.post("/api/v2/tasks/FakeTask/toggle")
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['name'], "FakeTask")
        self.assertEqual(data['enabled'], True)

        response = client.post("/api/v2/tasks/FakeTask/toggle")
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['name'], "FakeTask")
        self.assertEqual(data['enabled'], False)

    @mock.patch('core.taskmanager.run_task.delay')
    def test_run_task(self, mock_delay):
        response = client.post("/api/v2/tasks/FakeTask/run")
        data = response.json()
        mock_delay.assert_called_once_with("FakeTask")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['status'], "ok")


class ExportTaskTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()

        self.template = Template(
            name='RandomTemplate', template='<BLAH>').save()
        self.export_task = ExportTask(
            name='RandomExport',
            acts_on=['hostname'],
            ignore_tags=['ignore'],
            template_name='RandomTemplate').save()
        self.observable1 = Observable.add_text('export1.com', tags=['c2', 'legit'])
        self.observable2 = Observable.add_text('export2.com', tags=['c2'])
        self.observable3 = Observable.add_text('export3.com', tags=['c2', 'exclude'])
        taskmanager.TaskManager.register_task(ExportTask, task_name='RandomExport')

    def test_new_export(self):
        """Tests that new exports can be created."""
        response = client.post("/api/v2/tasks/export/new", json={
            "export": {
                "name": "RandomExport2",
                "acts_on": ["hostname"],
                "template_name": "RandomTemplate"
            }
        })
        data = response.json()
        self.assertEqual(data['acts_on'], ['hostname'])
        self.assertEqual(data['name'], 'RandomExport2')
        self.assertEqual(data['template_name'], 'RandomTemplate')

    def test_search_export(self):
        """Tests that exports can be searched."""
        response = client.post("/api/v2/tasks/search", json={"name": "RandomExport"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['tasks'][0]['name'], "RandomExport")
        self.assertEqual(data['tasks'][0]['type'], "export")
        self.assertEqual(data['tasks'][0]['ignore_tags'], ["ignore"])
        self.assertEqual(data['total'], 1)

    def test_patch_export(self):
        """Tests that exports can be patched."""
        patch_data = {
            'name': 'RandomExport',
            'template_name': 'RandomTemplate',
            'ignore_tags': ['ignore_new']
        }
        response = client.patch(
            f"/api/v2/tasks/export/RandomExport",
            json={"export": patch_data})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['name'], "RandomExport")
        self.assertEqual(data['ignore_tags'], ["ignore_new"])

    def test_patch_export_bad_template(self):
        """Tests that exports with bad template cannot be patched."""
        patch_data = {
            'name': 'RandomExport',
            'template_name': 'NOTEXIST',
            'ignore_tags': ['ignore_new']
        }
        response = client.patch(
            f"/api/v2/tasks/export/RandomExport",
            json={"export": patch_data})

        self.assertEqual(response.status_code, 422)
        data = response.json()
        self.assertEqual(
            data['detail'],
            "ExportTask could not be patched: Template NOTEXIST not found")

    def tearDown(self) -> None:
        database_arango.db.clear()
