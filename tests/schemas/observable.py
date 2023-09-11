from core.database_arango import ArangoDatabase
import datetime
import unittest

from core.schemas.observable import Observable
from core.schemas.observables.certificate import Certificate
from core.schemas.observables.url import Url
from core.schemas.observable import ObservableType
from core.schemas.observables.file import File
from core.schemas.observables.sha256 import SHA256

class ObservableTest(unittest.TestCase):

    def setUp(self) -> None:
        db = ArangoDatabase()
        db.connect()


    def test_certificate(self):
        cert = Certificate.get_or_create(value="146465498223")

        cert.issuer = "CN=Test"
        cert.serial_number = "146465498223"
        cert.subject = "CN=Test"
        cert.save()
        cert = Certificate.find(value="146465498223")
        self.assertEqual(cert.value, "146465498223")

    def test_file(self):
        file = File(value="146465498223", sha256="146465498223")
        file.save()

    def test_url(self):
        url = Url(value="https://www.google.com")
        url.save()

if __name__ == "__main__":
    unittest.main()
