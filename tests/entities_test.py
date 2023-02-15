import unittest
import sys
from os import path
from datetime import timedelta
from mongoengine import connect
from pyeti import YetiApi
import os

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

from core.config.config import yeti_config
from core.entities.malware import Malware
from core.entities import Exploit, ExploitKit, Actor, Campaign, Company, TTP

from core.user import User


class EntityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.db = connect("yeti", host=yeti_config.mongodb.host)

        DEFAULT_PERMISSIONS = {}
        DEFAULT_PERMISSIONS["admin"] = True
        user_default = User(username="test", permissions=DEFAULT_PERMISSIONS)

        self.yeti_client = YetiApi(
            api_key=user_default.api_key, url=yeti_config.pyeti.url
        )
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

    def test_company(self):
        compagny = Company(name="test").save()
        compagny_added = self.yeti_client.entity_get(compagny.id)
        self.assertEqual(compagny_added["name"], compagny.name)

    def test_exploit_kit(self):
        exploit_kit = ExploitKit(name="test").save()
        exploit_kit_added = self.yeti_client.entity_get(exploit_kit.id)
        self.assertEqual(exploit_kit_added["name"], exploit_kit.name)

    def test_exploit(self):
        exploit = Exploit(name="test").save()
        exploit_added = self.yeti_client.entity_get(exploit.id)
        self.assertEqual(exploit_added["name"], exploit.name)

    def test_ttp(self):
        ttp = TTP(name="test", killchain="1").save()
        ttp_added = self.yeti_client.entity_get(ttp.id)
        self.assertEqual(ttp_added["name"], ttp.name)

    def test_all(self):
        folder_entities = os.path.join(YETI_ROOT, "core", "entities")
        for file in os.listdir(folder_entities):
            if file.endswith(".py") and file != "__init__.py" and file != "entity.py":
                name_entity = file.split(".")[0]
                self.assertTrue(hasattr(self, f"test_{name_entity}"))

    def tearDown(self) -> None:
        self.db.drop_database("yeti")
        return super().tearDown()


if __name__ == "__main__":
    unittest.main()
