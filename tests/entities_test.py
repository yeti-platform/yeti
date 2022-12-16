import unittest
import sys
from os import path
from datetime import timedelta
from mongoengine import connect
from pyeti import YetiApi

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

from core.config.config import yeti_config

from core.entities.malware import MalwareFamily, Malware
from core.indicators import Regex, Indicator
from core.database import Link
from core.entities import TTP, Exploit, ExploitKit, Actor, Campaign, Company
from core.observables import Observable
from core.observables import Tag
from core.exports import Export, ExportTemplate


class EntityTest(unittest.TestCase):
    def setUp(self) -> None:
        db = connect("yeti", host=yeti_config.mongodb.host)
        db.drop_database("yeti")
        self.yeti_client = YetiApi(yeti_config.pyeti.url, api_key=yeti_config.pyeti.key)
        return super().setUp()
    
    def test_malware(self):
        malware = Malware(name="test").save()
        malware_added = self.yeti_client.entity_get(malware.id)
        self.assertEqual(malware_added["name"], malware.name)

    def test_actor(self):
        actor = Actor(name="test").save()
        actor_added = self.yeti_client.entity_get(actor.id)
        self.assertEqual(actor_added["name"], actor.name)

    def test_campaign(self):
        campaign = Campaign(name="test").save()
        campaign_added = self.yeti_client.entity_get(campaign.id)
        self.assertEqual(campaign_added["name"], campaign.name)

    def test_exploit(self):
        exploit = Exploit(name="test").save()
        exploit_added = self.yeti_client.entity_get(exploit.id)
        self.assertEqual(exploit_added["name"], exploit.name)

    def test_company(self):
        compagny = Company(name="test").save()
        compagny_added = self.yeti_client.entity_get(compagny.id)
        self.assertEqual(compagny_added["name"], compagny.name)

    def test_exploit_kit(self):
        exploit_kit = ExploitKit(name="test").save()
        exploit_kit_added = self.yeti_client.entity_get(exploit_kit.id)
        self.assertEqual(exploit_kit_added["name"], exploit_kit.name)


if __name__ == "__main__":
    unittest.main()
