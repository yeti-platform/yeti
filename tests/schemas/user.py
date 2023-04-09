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

    def test_set_user_password(self) -> None:
        self.user1.set_password("test")
        self.user1.save()

        user = UserSensitive.find(username='tomchop')
        assert user is not None
        self.assertEqual(user.username, "tomchop")
        self.assertTrue(user.verify_password("test"))
        self.assertFalse(user.verify_password("password"))
