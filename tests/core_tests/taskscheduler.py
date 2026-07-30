import importlib
import unittest
from unittest import mock

from arango.exceptions import ArangoClientError

from core import taskscheduler

REAL_IMPORT_MODULE = importlib.import_module
FAILING_PLUGIN = "plugins.feeds.public.urlhaus"


class GetPluginsListTest(unittest.TestCase):
    def test_database_error_during_registration_logs_as_error(self) -> None:
        """A plugin that imports fine but fails to register itself against
        the database (TaskManager.register_task runs at plugin import time)
        must be logged at ERROR, not folded into the same WARNING used for
        plugins whose own dependencies simply aren't installed -- those are
        very different failure classes operationally."""

        def fake_import_module(name, *args, **kwargs):
            if name == FAILING_PLUGIN:
                raise ArangoClientError("simulated database failure")
            return REAL_IMPORT_MODULE(name, *args, **kwargs)

        with mock.patch("importlib.import_module", side_effect=fake_import_module):
            with self.assertLogs(level="WARNING") as logs:
                taskscheduler.get_plugins_list()

        matching = [
            (record.levelname, record.message)
            for record in logs.records
            if FAILING_PLUGIN in record.message
        ]
        self.assertEqual(len(matching), 1)
        level, message = matching[0]
        self.assertEqual(level, "ERROR")
        self.assertIn("database", message)
