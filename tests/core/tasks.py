import datetime
import unittest

from core import database_arango
# from core.schemas.entity import Entity, Malware, ThreatActor, Tool
# from core.schemas.graph import Relationship
from core.schemas.observable import Observable
from core import taskmanager
from core.schemas.task import Task, TaskStatus, TaskType
from unittest import mock

class TasksTest(unittest.TestCase):

    def setUp(self) -> None:
        class FakeTask(Task):
            _DATA = ['asd1.com', 'asd2.com', 'asd3.com']
            _defaults = {
                "frequency": datetime.timedelta(hours=1),
                "type": "feed",
                # "source": "https://bazaar.abuse.ch/export/csv/recent/",
                "description": "Dummy feed",
            }

            def run(self):
                for item in self._DATA:
                    Observable.add_text(item)

        database_arango.db.clear()
        self.fake_task_class = FakeTask

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_register_task(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_task_class)
        task = taskmanager.TaskManager.get_task('FakeTask')
        self.assertEqual(task.name, 'FakeTask')
        self.assertEqual(task.type, TaskType.feed)
        self.assertEqual(task.description, 'Dummy feed')
        self.assertEqual(task.frequency, datetime.timedelta(hours=1))
        self.assertIsNone(task.last_run)

    def test_registered_task_is_in_db(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_task_class)
        task = Task.find(name='FakeTask')
        assert task is not None
        self.assertEqual(task.name, 'FakeTask')
        self.assertEqual(task.type, TaskType.feed)
        self.assertEqual(task.description, 'Dummy feed')
        self.assertEqual(task.frequency, datetime.timedelta(hours=1))
        self.assertIsNone(task.last_run)

    def test_run_task(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_task_class)
        observables = list(Observable.list())
        self.assertEqual(len(observables), 0)
        taskmanager.TaskManager.run_task('FakeTask')
        observables = list(Observable.list())
        self.assertEqual(len(observables), 3)
        task = self.fake_task_class.find(name='FakeTask')
        assert task is not None
        self.assertEqual(task.status, TaskStatus.completed)
        self.assertIsNotNone(task.last_run)

    def test_run_disabled_task(self) -> None:
        self.fake_task_class._defaults['enabled'] = False
        taskmanager.TaskManager.register_task(self.fake_task_class)
        taskmanager.TaskManager.run_task('FakeTask')
        observables = list(Observable.list())
        self.assertEqual(len(observables), 0)
        task = self.fake_task_class.find(name='FakeTask')
        assert task is not None
        self.assertFalse(task.enabled)
        self.assertEqual(task.status, TaskStatus.failed)
        self.assertEqual(task.status_message, 'Task is disabled.')

    def test_failed_task(self) -> None:
        self.fake_task_class.run = mock.MagicMock(
            side_effect=Exception('Test exception'))
        taskmanager.TaskManager.register_task(self.fake_task_class)
        taskmanager.TaskManager.run_task('FakeTask')
        task = self.fake_task_class.find(name='FakeTask')
        assert task is not None
        self.assertEqual(task.status, TaskStatus.failed)
        self.assertEqual(task.status_message, 'Test exception')
