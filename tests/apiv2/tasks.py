import datetime
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from core import database_arango, taskmanager
from core.schemas.task import Task
from core.web import webapp

client = TestClient(webapp.app)

class FakeTask(Task):
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
        self.assertEqual(data['enabled'], False)

        response = client.post("/api/v2/tasks/FakeTask/toggle")
        data = response.json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['name'], "FakeTask")
        self.assertEqual(data['enabled'], True)

    @mock.patch('core.taskmanager.run_task.delay')
    def test_run_task(self, mock_delay):
        response = client.post("/api/v2/tasks/FakeTask/run")
        data = response.json()
        mock_delay.assert_called_once_with("FakeTask")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data['status'], "ok")
