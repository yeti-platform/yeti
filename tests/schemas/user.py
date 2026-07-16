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

    def test_create_api_key(self) -> None:
        self.user1.create_api_key("apikey")
        old_api_key = self.user1.api_keys["apikey"]
        self.user1.create_api_key("apikey")
        self.user1.save()

        user = UserSensitive.find(username="tomchop")
        new_api_key = user.api_keys["apikey"]
        self.assertNotEqual(old_api_key.created, new_api_key.created)
        self.assertEqual(old_api_key.sub, new_api_key.sub)

    def test_create_api_key_when_api_keys_none(self) -> None:
        # api_keys can be None (delete_api_key persists it transiently);
        # create_api_key must initialize it rather than crashing.
        self.user1.api_keys = None
        self.user1.create_api_key("apikey")
        self.assertIn("apikey", self.user1.api_keys)

    def test_validate_api_key_payload_with_none_api_keys(self) -> None:
        # delete_api_key transiently persists api_keys=None; validation must
        # degrade to "invalid credentials" rather than raising TypeError.
        self.user1.api_keys = None
        with self.assertRaises(ValueError):
            self.user1.validate_api_key_payload({"sub": "tomchop", "name": "apikey"})

    def test_delete_api_key(self) -> None:
        user = UserSensitive.find(username="tomchop")
        self.assertEqual(len(user.api_keys), 0)

        self.user1.create_api_key("apikey")
        self.user1.save()

        user = UserSensitive.find(username="tomchop")
        self.assertEqual(len(user.api_keys), 1)

        user.delete_api_key("apikey")
        user.save()
        user = UserSensitive.find(username="tomchop")
        self.assertEqual(len(user.api_keys), 0)
