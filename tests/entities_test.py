import unittest
import sys
from os import path
from mongoengine import connect
from pyeti import YetiApi
import os

YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

from core.config.config import yeti_config

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
        malware_name = "test_malware"
        malware = self.yeti_client.add_malware(name=malware_name)
        malware_added = self.yeti_client.entity_search(name=malware_name)
        self.assertEqual(malware_added[0]["name"], malware_name)

    def test_actor(self):
        actor_name = "test_actor"
        actor = self.yeti_client.add_actor(name=actor_name)
        actor_added = self.yeti_client.entity_search(name=actor_name)
        self.assertEqual(actor_added[0]["name"], actor_name)


    def test_campaign(self):
        campaign_name = "test_campaign"
        campaign = self.yeti_client.add_campaign(name=campaign_name)
        campaign_added = self.yeti_client.entity_search(name=campaign_name)
        self.assertEqual(campaign_added[0]["name"], campaign_name)

    def test_company(self):
        company_name = "test_company"
        company = self.yeti_client.add_company(name=company_name)
        company_added = self.yeti_client.entity_search(name=company_name)
        self.assertEqual(company_added[0]["name"], company_name)


    def test_exploit(self):
        exploit_name = "test_exploit"
        exploit = self.yeti_client.add_exploit(name=exploit_name)
        exploit_added = self.yeti_client.entity_search(name=exploit_name)
        self.assertEqual(exploit_added[0]["name"], exploit_name)

    def test_ttp(self):
        ttp_name = "test_ttp"
        ttp = self.yeti_client.add_ttp(name=ttp_name, killchain="Reconnaissance")
        ttp_added = self.yeti_client.entity_search(name=ttp_name)
        self.assertEqual(ttp_added[0]["name"], ttp_name)

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
