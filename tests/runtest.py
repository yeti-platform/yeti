import unittest
import sys
from os import path
from datetime import timedelta
from mongoengine import connect

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

from core.config.config import yeti_config

from core.entities.malware import MalwareFamily, Malware
from core.indicators import Regex, Indicator
from core.database import Link
from core.entities import TTP, Exploit, ExploitKit
from core.observables import Observable
from core.observables import Tag
from core.exports import Export, ExportTemplate


class EntityTest(unittest.TestCase):
    def test_malware(self):
        db = connect("yeti", host=yeti_config.mongodb.host)
        db.drop_database("yeti")
        malware = Malware(name="test").save()
        self.assertEqual(malware.name, "test")


if __name__ == "__main__":
    unittest.main()
