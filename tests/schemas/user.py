import datetime

from core import database_arango
from core.schemas.user import User, UserSensitive

import unittest


class UserTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.clear()
        self.user1 = UserSensitive(username="tomchop").save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_has_api_key(self) -> None:
        self.assertRegex(self.user1.api_key, r"[a-f0-9]{32}")
        self.assertTrue(self.user1.api_key)

    def test_set_user_password(self) -> None:
        self.user1.set_password("test")
        self.user1.save()

        user = UserSensitive.find(username="tomchop")
        assert user is not None
        self.assertEqual(user.username, "tomchop")
        self.assertTrue(user.verify_password("test"))
        self.assertFalse(user.verify_password("password"))

    def test_reset_api_key(self) -> None:
        old_api_key = self.user1.api_key
        self.user1.reset_api_key()
        self.user1.save()

        user = UserSensitive.find(username="tomchop")
        assert user is not None
        self.assertNotEqual(old_api_key, self.user1.api_key)
        self.assertRegex(user.api_key, r"[a-f0-9]{64}")

    def test_reset_api_key_with_param(self) -> None:
        self.user1.reset_api_key(api_key="1234123412341234123412341234123412341234123412341234123412341234")
        self.user1.save()

        user = UserSensitive.find(username="tomchop")
        assert user is not None
        self.assertEqual(self.user1.api_key, "1234123412341234123412341234123412341234123412341234123412341234")
