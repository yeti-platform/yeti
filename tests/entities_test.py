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
            api_key=user_default.api_key, url="http://localhost:5000/api"
        )
        return super().setUp()

    def test_add_malware(self):
        """Adds a malware with tags and tests for that value and tags match."""
        malware_name = "test_malware"
        self.yeti_client.entity_add(
            name=malware_name, entity_type="malware", tags=["asd"]
        )
        malware = self.yeti_client.entity_search(name=malware_name)
        self.assertEqual(malware[0]["name"], malware_name)

    def test_add_campaign(self):
        """Adds a campaign with tags and tests for that value and tags match."""
        campaign_name = "test_campaign"
        self.yeti_client.entity_add(
            name=campaign_name, entity_type="campaign", tags=["asd"]
        )
        campaign = self.yeti_client.entity_search(name=campaign_name)
        self.assertEqual(campaign[0]["name"], campaign_name)

    def test_add_actor(self):
        """Adds an actor with tags and tests for that value and tags match."""
        actor_name = "test_actor"
        self.yeti_client.entity_add(name=actor_name, entity_type="actor", tags=["asd"])
        actor = self.yeti_client.entity_search(name=actor_name)
        self.assertEqual(actor[0]["name"], actor_name)

    def test_add_ttp(self):
        """Adds a ttp with tags and tests for that value and tags match."""
        ttp_name = "test_ttp"
        self.yeti_client.entity_add(
            name=ttp_name, entity_type="ttp", tags=["asd"], killchain="1"
        )
        ttp = self.yeti_client.entity_search(name=ttp_name)
        self.assertEqual(ttp[0]["name"], ttp_name)

    def test_add_exploit(self):
        """Adds an exploit with tags and tests for that value and tags match."""
        exploit_name = "test_exploit"
        self.yeti_client.entity_add(
            name=exploit_name, entity_type="exploit", tags=["asd"]
        )
        exploit = self.yeti_client.entity_search(name=exploit_name)
        self.assertEqual(exploit[0]["name"], exploit_name)

    def test_add_compagny(self):
        """Adds a compagny with tags and tests for that value and tags match."""
        compagny_name = "test_compagny"
        self.yeti_client.entity_add(
            name=compagny_name, entity_type="compagny", tags=["asd"]
        )
        compagny = self.yeti_client.entity_search(name=compagny_name)
        self.assertEqual(compagny[0]["name"], compagny_name)

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
