import datetime
import unittest
from typing import ClassVar
from unittest import mock

from core import database_arango, taskmanager
from core.config.config import yeti_config
from core.schemas.observable import Observable
from core.schemas.task import (AnalyticsTask, ExportTask, FeedTask,
                               OneShotTask, Task, TaskParams, TaskStatus,
                               TaskType)
from core.schemas.template import Template


class TaskTest(unittest.TestCase):
    def setUp(self) -> None:
        class FakeTask(FeedTask):
            # classvar
            _DATA: ClassVar[list[str]] = ["asd1.com", "asd2.com", "asd3.com"]
            _defaults: ClassVar[dict] = {
                "frequency": datetime.timedelta(hours=1),
                # "source": "https://bazaar.abuse.ch/export/csv/recent/",
                "description": "Dummy feed",
                "enabled": True,
            }

            def run(self):
                for item in self._DATA:
                    Observable.add_text(item)

        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        self.fake_task_class = FakeTask

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_register_task(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_task_class)
        task = taskmanager.TaskManager.get_task("FakeTask")
        self.assertEqual(task.name, "FakeTask")
        self.assertEqual(task.type, TaskType.feed)
        self.assertEqual(task.description, "Dummy feed")
        self.assertEqual(task.frequency, datetime.timedelta(hours=1))
        self.assertIsNone(task.last_run)

    def test_registered_task_is_in_db(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_task_class)
        task = Task.find(name="FakeTask")
        assert task is not None
        self.assertEqual(task.name, "FakeTask")
        self.assertEqual(task.type, TaskType.feed)
        self.assertEqual(task.description, "Dummy feed")
        self.assertEqual(task.frequency, datetime.timedelta(hours=1))
        self.assertIsNone(task.last_run)

    def test_task_types(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_task_class)
        task = taskmanager.TaskManager.get_task("FakeTask")
        tasks, total = Task.filter({"type": "feed"})
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].name, "FakeTask")
        self.assertIsInstance(tasks[0], Task)
        task = self.fake_task_class.find(name="FakeTask")
        self.assertIsInstance(task, self.fake_task_class)

    def test_run_task(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_task_class)
        observables = list(Observable.list())
        self.assertEqual(len(observables), 0)
        taskmanager.TaskManager.run_task("FakeTask", TaskParams())
        observables = list(Observable.list())
        self.assertEqual(len(observables), 3)
        task = self.fake_task_class.find(name="FakeTask")
        assert task is not None
        self.assertEqual(task.status, TaskStatus.completed)
        self.assertIsNotNone(task.last_run)

    def test_run_disabled_task(self) -> None:
        self.fake_task_class._defaults["enabled"] = False
        taskmanager.TaskManager.register_task(self.fake_task_class)
        taskmanager.TaskManager.run_task("FakeTask", TaskParams())
        observables = list(Observable.list())
        self.assertEqual(len(observables), 0)
        task = self.fake_task_class.find(name="FakeTask")
        assert task is not None
        self.assertFalse(task.enabled)
        self.assertEqual(task.status, TaskStatus.failed)
        self.assertEqual(task.status_message, "Task is disabled.")

    def test_failed_task(self) -> None:
        self.fake_task_class.run = mock.MagicMock(
            side_effect=Exception("Test exception")
        )
        taskmanager.TaskManager.register_task(self.fake_task_class)
        taskmanager.TaskManager.run_task("FakeTask", TaskParams())
        task = self.fake_task_class.find(name="FakeTask")
        assert task is not None
        self.assertEqual(task.status, TaskStatus.failed)
        self.assertEqual(task.status_message, "Test exception")


class AnalyticsTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        self.observable1 = Observable.add_text("asd1.com")
        self.observable2 = Observable.add_text("asd2.com")
        self.observable3 = Observable.add_text("asd3.com")
        self.observable4 = Observable.add_text("8.8.8.8")

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_run_analytics_task(self):
        """Tests that the each function is called for each filtered observable."""
        mock_inner_each = mock.MagicMock()

        class FakeTask(AnalyticsTask):
            _defaults = {
                "frequency": datetime.timedelta(hours=1),
                "type": "analytics",
                "description": "Dummy analytics",
                "enabled": True,
            }

            acts_on: list[str] = ["hostname"]

            def each(self, observable):
                import logging
                logging.debug("Running FakeTask")

                # Do nothing, except call the mock.
                mock_inner_each(observable.value)

        taskmanager.TaskManager.register_task(FakeTask)
        taskmanager.TaskManager.run_task("FakeTask", TaskParams())
        task = FakeTask.find(name="FakeTask")
        assert task is not None
        self.assertEqual(task.status, TaskStatus.completed, task.status_message)
        self.assertIsNotNone(task.last_run)
        mock_inner_each.assert_has_calls(
            [
                mock.call(self.observable1.value),
                mock.call(self.observable2.value),
                mock.call(self.observable3.value),
            ]
        )
        self.assertEqual(mock_inner_each.call_count, 3)

    @mock.patch("core.schemas.task.now")
    def test_run_analytics_sets_last_analysis(self, mock_now):
        """Tests that the analytics will set the last_analysis field."""
        mock_now.return_value = datetime.datetime(1970, 1, 1)

        class FakeTask(AnalyticsTask):
            _defaults = {
                "frequency": datetime.timedelta(hours=1),
                "type": "analytics",
                "description": "Dummy analytics",
                "enabled": True,
            }

            acts_on: list[str] = ["ipv4"]

            def each(self, observable):
                pass

        taskmanager.TaskManager.register_task(FakeTask)
        taskmanager.TaskManager.run_task("FakeTask", TaskParams())
        db_observable = Observable.get(self.observable4.id)
        assert db_observable is not None
        self.assertEqual(
            db_observable.last_analysis, {"FakeTask": datetime.datetime(1970, 1, 1)}
        )


class OneShotTaskTest(unittest.TestCase):
    def setUp(self) -> None:
        class FakeOneShotTask(OneShotTask):
            # classvar
            _defaults = {
                "name": "FakeOneShotTask",
                "description": "Add fake metadata to hostname observable",
                "enabled": True
            }

            acts_on: list[str] = ["hostname"]

            def each(self, observable):
                observable.add_context("test", {"test": "test"})

        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        self.fake_oneshot_task_class = FakeOneShotTask
        observable = Observable.add_text("asd1.com")
        observable.tag(["c2", "legit"])
        observable.save()

    def test_register_task(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_oneshot_task_class)
        task = taskmanager.TaskManager.get_task("FakeOneShotTask")
        self.assertEqual(task.name, "FakeOneShotTask")
        self.assertEqual(task.type, TaskType.oneshot)
        self.assertEqual(task.description, "Add fake metadata to hostname observable")
        self.assertIsNone(task.last_run)

    def test_registered_task_is_in_db(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_oneshot_task_class)
        task = Task.find(name="FakeOneShotTask")
        assert task is not None
        self.assertEqual(task.name, "FakeOneShotTask")
        self.assertEqual(task.type, TaskType.oneshot)
        self.assertEqual(task.description, "Add fake metadata to hostname observable")
        self.assertIsNone(task.last_run)

    def test_task_types(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_oneshot_task_class)
        task = taskmanager.TaskManager.get_task("FakeOneShotTask")
        tasks, total = Task.filter({"type": "oneshot"})
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].name, "FakeOneShotTask")
        self.assertIsInstance(tasks[0], Task)
        task = self.fake_oneshot_task_class.find(name="FakeOneShotTask")
        self.assertIsInstance(task, self.fake_oneshot_task_class)

    def test_run_oneshot_task(self) -> None:
        taskmanager.TaskManager.register_task(self.fake_oneshot_task_class)
        taskmanager.TaskManager.run_task("FakeOneShotTask", TaskParams(params={"value": "asd1.com"}))
        observable = Observable.find(value="asd1.com")
        self.assertEqual(observable.context, [{'source': 'test', 'test': 'test'}])
        task = self.fake_oneshot_task_class.find(name="FakeOneShotTask")
        assert task is not None
        self.assertEqual(task.status, TaskStatus.completed)
        self.assertIsNotNone(task.last_run)

    

class ExportTaskTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        self.observable1 = Observable.add_text("asd1.com", tags=["c2", "legit"])
        self.observable2 = Observable.add_text("asd2.com", tags=["c2"])
        self.observable3 = Observable.add_text("asd3.com", tags=["c2", "exclude"])
        self.observable4 = Observable.add_text("asd4.com", tags=["legit"])
        self.observable5 = Observable.add_text("asd5.com")
        self.observable6 = Observable.add_text("127.0.0.1")
        self.template = Template(name="RandomTemplate", template="<BLAH>").save()
        self.export_task = ExportTask(
            name="RandomExport",
            acts_on=["hostname"],
            template_name="RandomTemplate",
            enabled=True,
        ).save()
        taskmanager.TaskManager.register_task(ExportTask, task_name="RandomExport")

    @mock.patch("core.schemas.template.Template.render")
    def test_run_export_task(self, mock_render):
        """Tests that the each function is called for each filtered observable."""
        taskmanager.TaskManager.run_task("RandomExport", TaskParams())
        task = ExportTask.find(name="RandomExport")
        assert task is not None
        self.assertEqual(task.status, TaskStatus.completed, task.status_message)
        observable_list, filename = mock_render.call_args[0]
        self.assertTrue(filename.endswith("/exports/randomexport"))
        self.assertEqual(len(observable_list), 4)

        self.assertEqual(observable_list[0].value, self.observable1.value)
        self.assertEqual(set(observable_list[0].tags), set(self.observable1.tags))

        self.assertIsNotNone(task.last_run)

    @mock.patch("core.schemas.template.Template.render")
    def test_run_export_task_with_config_path(self, mock_render):
        """Tests that the each function is called for each filtered observable."""
        previous = yeti_config.get('system', 'export_path')
        yeti_config.system.export_path = "/tmp"
        taskmanager.TaskManager.run_task("RandomExport", TaskParams())
        task = ExportTask.find(name="RandomExport")
        assert task is not None
        self.assertEqual(task.status, TaskStatus.completed, task.status_message)
        _, filename = mock_render.call_args[0]
        self.assertEqual(filename, "/tmp/exports/randomexport")
        yeti_config.system.export_path = previous

    def test_tag_filtering(self):
        """Tests that the tag filtering works as intended."""
        task = ExportTask.find(name="RandomExport")

        # We expect all tagged hostnames to be returned
        results = task.get_tagged_data(
            acts_on=["hostname"],
            include_tags=[],
            exclude_tags=[],
            ignore_tags=[],
            fresh_tags=True,
        )
        self.assertEqual(
            set([r.value for r in results]),
            set(["asd1.com", "asd2.com", "asd3.com", "asd4.com"]),
        )

        # We expect all hostnames that aren't tagged "c2"
        results = task.get_tagged_data(
            acts_on=["hostname"],
            include_tags=[],
            exclude_tags=["c2"],
            ignore_tags=[],
            fresh_tags=True,
        )
        self.assertEqual(results[0].value, "asd4.com")
        self.assertEqual(len(results), 1)

        # We expect all hostnames that are tagged "c2" but NOT "exclude"
        results = task.get_tagged_data(
            acts_on=["hostname"],
            include_tags=["c2"],
            exclude_tags=["exclude"],
            ignore_tags=[],
            fresh_tags=True,
        )
        self.assertEqual({r.value for r in results}, {"asd1.com", "asd2.com"})
        self.assertEqual(len(results), 2)

        # We expect all tagged hostnames, excpet if the only tag is "legit"
        results = task.get_tagged_data(
            acts_on=["hostname"],
            include_tags=[],
            exclude_tags=[],
            ignore_tags=["legit"],
            fresh_tags=True,
        )
        self.assertEqual(
            {r.value for r in results}, {"asd1.com", "asd2.com", "asd3.com"}
        )
        self.assertEqual(len(results), 3)
