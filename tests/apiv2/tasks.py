import datetime
import logging
import sys
import unittest
from unittest import mock

from core import database_arango, taskmanager
from core.schemas.observable import Observable
from core.schemas.task import ExportTask, FeedTask
from core.schemas.template import Template
from core.schemas.user import UserSensitive
from core.web import webapp
from fastapi.testclient import TestClient

client = TestClient(webapp.app)


class FakeTask(FeedTask):
    _DATA = ["asd1.com", "asd2.com", "asd3.com"]
    _defaults = {
        "frequency": datetime.timedelta(hours=1),
        "type": "feed",
        "description": "Dummy feed",
    }

    def run(self):
        pass


class TaskTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        user = UserSensitive(username="test", password="test", enabled=True).save()
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user.api_key}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}
        taskmanager.TaskManager.register_task(FakeTask)

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_search_tasks(self):
        response = client.post("/api/v2/tasks/search", json={"query": {"name": "FakeTask"}})
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["tasks"][0]["name"], "FakeTask")
        self.assertEqual(data["total"], 1)

    def test_toggle_task(self):
        response = client.post("/api/v2/tasks/FakeTask/toggle")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["name"], "FakeTask")
        self.assertEqual(data["enabled"], True)

        response = client.post("/api/v2/tasks/FakeTask/toggle")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["name"], "FakeTask")
        self.assertEqual(data["enabled"], False)

    @mock.patch("core.taskscheduler.run_task.delay")
    def test_run_task(self, mock_delay):
        response = client.post("/api/v2/tasks/FakeTask/run")
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["status"], "ok")
        mock_delay.assert_called_once_with("FakeTask", '{"params":{}}')

    @mock.patch("core.taskscheduler.run_task.delay")
    def test_run_task_with_params(self, mock_delay):
        response = client.post(
            "/api/v2/tasks/FakeTask/run", json={"params": {"value": "test"}}
        )
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["status"], "ok")
        mock_delay.assert_called_once_with("FakeTask", '{"params":{"value":"test"}}')


class ExportTaskTest(unittest.TestCase):
    def setUp(self) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        user = UserSensitive(username="test", password="test", enabled=True).save()
        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user.api_key}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

        self.template = Template(name="RandomTemplate", template="<BLAH>").save()
        self.export_task = ExportTask(
            name="RandomExport",
            acts_on=["hostname"],
            ignore_tags=["ignore"],
            template_name="RandomTemplate",
        ).save()
        self.observable1 = Observable.add_text("export1.com", tags=["c2", "legit"])
        self.observable2 = Observable.add_text("export2.com", tags=["c2"])
        self.observable3 = Observable.add_text("export3.com", tags=["c2", "exclude"])
        taskmanager.TaskManager.register_task(ExportTask, task_name="RandomExport")

    def test_new_export(self):
        """Tests that new exports can be created."""
        response = client.post(
            "/api/v2/tasks/export/new",
            json={
                "export": {
                    "name": "RandomExport2",
                    "acts_on": ["hostname"],
                    "template_name": "RandomTemplate",
                }
            },
        )
        data = response.json()
        self.assertEqual(data["acts_on"], ["hostname"])
        self.assertEqual(data["name"], "RandomExport2")
        self.assertEqual(data["template_name"], "RandomTemplate")

    def test_search_export(self):
        """Tests that exports can be searched."""
        response = client.post("/api/v2/tasks/search", json={"query": {"name": "RandomExport"}})
        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["tasks"][0]["name"], "RandomExport")
        self.assertEqual(data["tasks"][0]["type"], "export")
        self.assertEqual(data["tasks"][0]["ignore_tags"], ["ignore"])
        self.assertEqual(data["total"], 1)

    def test_patch_export(self):
        """Tests that exports can be patched."""
        patch_data = {
            "name": "RandomExport",
            "template_name": "RandomTemplate",
            "ignore_tags": ["ignore_new"],
        }
        response = client.patch(
            "/api/v2/tasks/export/RandomExport", json={"export": patch_data}
        )

        data = response.json()
        self.assertEqual(response.status_code, 200, data)
        self.assertEqual(data["name"], "RandomExport")
        self.assertEqual(data["ignore_tags"], ["ignore_new"])

    def test_patch_export_bad_template(self):
        """Tests that exports with bad template cannot be patched."""
        patch_data = {
            "name": "RandomExport",
            "template_name": "NOTEXIST",
            "ignore_tags": ["ignore_new"],
        }
        response = client.patch(
            "/api/v2/tasks/export/RandomExport", json={"export": patch_data}
        )

        self.assertEqual(response.status_code, 422)
        data = response.json()
        self.assertEqual(
            data["detail"],
            "ExportTask could not be patched: Template NOTEXIST not found",
        )

    def test_delete_export(self):
        """Tests that exports can be deleted."""
        response = client.delete("/api/v2/tasks/export/RandomExport")
        self.assertEqual(response.status_code, 200)
        # verify the export doesn't exist
        response = client.post("/api/v2/tasks/search", json={"query": {"name": "RandomExport"}})
        data = response.json()
        self.assertEqual(data["total"], 0)

    def tearDown(self) -> None:
        database_arango.db.clear()
