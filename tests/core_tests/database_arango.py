import unittest
from unittest import mock

from core import database_arango


class ConnectRetryTest(unittest.TestCase):
    def test_connect_retries_and_exits_cleanly_on_unreachable_host(self) -> None:
        """connect() must retry (not crash with an unhandled exception) when
        ArangoDB is unreachable, and exit cleanly once it exhausts its
        retries. python-arango's host resolver wraps a failed connection
        attempt in the builtin ConnectionError rather than
        requests.exceptions.ConnectionError, so the retry loop's except
        clause needs to catch both."""
        db = database_arango.ArangoDatabase()
        with mock.patch("core.database_arango.time.sleep"):
            with self.assertRaises(SystemExit):
                db.connect(host="127.0.0.1", port=1, username="root", password="")
