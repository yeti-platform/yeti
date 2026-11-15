import logging
import unittest

from core import database_arango
from core.schemas.observable import Observable
from plugins.feeds.public import otx_alienvault


class OTXAlienvaultTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.addCleanup(database_arango.db.truncate)
        previous = logging.root.manager.disable
        logging.disable(logging.NOTSET)
        self.addCleanup(logging.disable, previous)

    def test_an_invalid_indicator_is_skipped(self) -> None:
        feed = otx_alienvault.OTXAlienvault(
            **otx_alienvault.OTXAlienvault._defaults.copy()
        )
        pulse = {
            "id": "pulse1",
            "name": "Pulse",
            "description": "A pulse",
            "references": [],
            "tags": ["otx"],
            "indicators": [
                {
                    "type": "hostname",
                    "indicator": "not a hostname!",
                    "description": "",
                    "created": "2026-10-28T00:00:00",
                },
                {
                    "type": "hostname",
                    "indicator": "evil.example.com",
                    "description": "",
                    "created": "2026-10-28T00:00:00",
                },
            ],
        }

        with self.assertLogs(level=logging.WARNING) as logs:
            feed.analyze(pulse)

        self.assertIn("not a hostname!", "\n".join(logs.output))
        self.assertIsNone(Observable.find(value="not a hostname!"))
        self.assertIsNotNone(Observable.find(value="evil.example.com"))
