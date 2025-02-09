import unittest

from core import database_arango
from core.schemas.user import UserSensitive


class UserTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.user1 = UserSensitive(username="tomchop").save()

    def test_set_user_password(self) -> None:
        self.user1.set_password("test")
        self.user1.save()

        user = UserSensitive.find(username="tomchop")
        assert user is not None
        self.assertEqual(user.username, "tomchop")
        self.assertTrue(user.verify_password("test"))
        self.assertFalse(user.verify_password("password"))

    def test_reset_api_key(self) -> None:
        self.user1.create_api_key("apikey")
        old_api_key = self.user1.api_keys["apikey"]
        self.user1.create_api_key("apikey")
        self.user1.save()

        user = UserSensitive.find(username="tomchop")
        new_api_key = user.api_keys["apikey"]
        self.assertNotEqual(old_api_key.created, new_api_key.created)
        self.assertEqual(old_api_key.sub, new_api_key.sub)
