import unittest
import sys
from os import path
from datetime import timedelta
from pyeti import YetiApi
from mongoengine import connect
import os


YETI_ROOT = path.normpath(path.dirname(path.dirname(path.abspath(__file__))))
sys.path.append(YETI_ROOT)

from core.config.config import yeti_config
from core.observables.asn import AutonomousSystem
from core.observables.bitcoin import Bitcoin
from core.observables.certificate import Certificate
from core.observables.file import File
from core.observables.hostname import Hostname
from core.observables.ip import Ip
from core.observables.email import Email
from core.observables.mac_address import MacAddress
from core.observables.hash import Hash
from core.observables.url import Url
from core.observables.text import Text
from core.observables.path import Path

from core.user import User


class ObservableTest(unittest.TestCase):
    def setUp(self) -> None:
        self.db = connect("yeti", host=yeti_config.mongodb.host)  # type: ignore
        # type: ignore
        DEFAULT_PERMISSIONS = {}
        DEFAULT_PERMISSIONS["admin"] = True
        user_default = User(username="test", permissions=DEFAULT_PERMISSIONS)

        self.yeti_client = YetiApi(
            api_key=user_default.api_key, url=yeti_config.pyeti.url  # type: ignore
        )
        return super().setUp()

    def test_asn(self):
        asn = self.yeti_client.observable_add(value="1234",type_obs="AutonomousSystem")
        if not asn:
            self.assertIsNotNone(asn)
        
        asn_added = self.yeti_client.observable_search(value="1234")
        if not asn_added:
            self.assertIsNotNone(asn_added)

        self.assertEqual(asn_added[0]["value"], "1234")

    def test_bitcoin(self):
        bitcoin = self.yeti_client.observable_add("115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn")
        if not bitcoin:
            self.assertIsNotNone(bitcoin)
        bitcoin_added = self.yeti_client.observable_search(value="115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn")
        self.assertEqual(bitcoin_added[0]["value"], "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn")

    def test_certificate(self):
        certificate = Certificate(value="test").save()
        certificate_added = self.yeti_client.observable_search(value=certificate.value)
        self.assertEqual(certificate_added[0]["value"], certificate.value)

    def test_file(self):
        file = File(value="test").save()
        file_added = self.yeti_client.observable_search(value=file.value)
        self.assertEqual(file_added[0]["value"], file.value)

    def test_hostname(self):
        hostname = self.yeti_client.observable_add(
            value="www.test.com"
        )
        if not hostname:
            self.assertIsNotNone(hostname)
        
        hostname_added = self.yeti_client.observable_search(value="www.test123.com")
        if not hostname_added:
            self.assertIsNotNone(hostname_added)
            
        self.assertEqual(hostname_added[0]["value"], "www.test123.com")

    def test_ip(self):
        ip = self.yeti_client.observable_add(value="1.1.1.1")
        if not ip:
            self.assertIsNot(ip, None)
        ip_added = self.yeti_client.observable_search(value="1.1.1.1")
        self.assertEqual(ip_added[0]["value"], "1.1.1.1")

    def test_email(self):
        email = self.yeti_client.observable_add(value="test@test.com")
        if not email:
            self.assertIsNotNone(email)
        
        email_added = self.yeti_client.observable_search(value="test@test.com")
        self.assertEqual(email_added[0]["value"], "test@test.com")

    def test_mac_address(self):
        mac_address = self.yeti_client.observable_add("00:00:00:00:00:00")
        if not mac_address:
            self.assertIsNotNone(mac_address)

        mac_address_added = self.yeti_client.observable_search(value="00:00:00:00:00:00")
        if not mac_address_added:
            self.assertIsNotNone(mac_address_added)
        self.assertEqual(mac_address_added[0]["value"], "00:00:00:00:00:00")

    def test_hash(self):
        hash = self.yeti_client.observable_add("08be2c7239acb9557454088bba877a245c8ef9b0e9eb389c65a98e1c752c5709")
        if not hash:
            self.assertIsNotNone(hash)
           
        hash_added = self.yeti_client.observable_search(value="08be2c7239acb9557454088bba877a245c8ef9b0e9eb389c65a98e1c752c5709")
        if not hash_added:
            self.assertIsNotNone(hash_added)
        self.assertEqual(hash_added[0]["value"],"08be2c7239acb9557454088bba877a245c8ef9b0e9eb389c65a98e1c752c5709")

    def test_url(self):
        url = self.yeti_client.observable_add(value="http://www.test.com")
        if not url:
            self.assertIsNotNone(url)

        url_added = self.yeti_client.observable_search("http://www.test.com")
        if not url_added:
            self.assertIsNotNone(url_added)
        self.assertEqual(url_added[0]["value"], "http://www.test.com")

    def test_text(self):
        text = self.yeti_client.observable_add(value="test12345", type_obs="Text")
        text_added = self.yeti_client.observable_search(value="test12345")
        self.assertEqual(text_added[0]["value"], "test12345")

    def test_path(self):
        path = self.yeti_client.observable_add("/test/test",type_obs="Path")
        if not path:
            self.assertIsNotNone(path)
        path_added = self.yeti_client.observable_search(value="/test/test")
        if not path_added:
            self.assertIsNotNone(path_added)
        self.assertEqual(path_added[0]["value"],"/test/test")

    def test_all(self):
        folder_entities = os.path.join(YETI_ROOT, "core", "observables")
        for file in os.listdir(folder_entities):
            if (
                file.endswith(".py")
                and file != "__init__.py"
                and file != "tag.py"
                and file != "observable.py"
                and file != "helpers.py"
            ):
                name_entity = file.split(".")[0]
                self.assertTrue(
                    hasattr(self, f"test_{name_entity}"),
                    msg=f"test_{name_entity} not found",
                )

    def tearDown(self) -> None:
        self.db.drop_database("yeti")
        return super().tearDown()


if __name__ == "__main__":
    unittest.main()
