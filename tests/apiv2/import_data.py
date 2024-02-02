import logging
import sys
import unittest

from fastapi.testclient import TestClient

from core import database_arango
from core.schemas.user import UserSensitive
from core.web import webapp

client = TestClient(webapp.app)


class ImportData(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        logging.disable(sys.maxsize)
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        user = UserSensitive(username="test")
        user.set_password("test")
        user.save()

        token_data = client.post(
            "/api/v2/auth/api-token", headers={"x-yeti-apikey": user.api_key}
        ).json()
        client.headers = {"Authorization": "Bearer " + token_data["access_token"]}

        cls.path_json = "tests/misp_test_data/misp_event.json"

    def test_import_misp(self):
        logging.info("Test import misp")
        with open(self.path_json, "rb") as fichier:
            files = {"misp_file_json": (self.path_json, fichier)}
            r = client.post("/api/v2/import_data/import_misp_json", files=files)
            self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()
