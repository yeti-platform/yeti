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
from core.observables.tag import Tag

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

    def test_asn(self):
        asn = AutonomousSystem(value="123").save()
        asn_added = self.yeti_client.observable_search(value=asn.value)
        self.assertEqual(asn_added[0]["value"], asn.value)

    def test_bitcoin(self):
        bitcoin = Bitcoin(value="115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn").save()
        bitcoin_added = self.yeti_client.observable_search(value=bitcoin.value)
        self.assertEqual(bitcoin_added[0]["value"], bitcoin.value)

    def test_certificate(self):
        certificate = Certificate(value="test").save()
        certificate_added = self.yeti_client.observable_search(value=certificate.value)
        self.assertEqual(certificate_added[0]["value"], certificate.value)

    def test_file(self):
        file = File(value="test").save()
        file_added = self.yeti_client.observable_search(value=file.value)
        self.assertEqual(file_added[0]["value"], file.value)

    def test_hostname(self):
        hostname = Hostname(value="www.test.com").save()
        hostname_added = self.yeti_client.observable_search(value=hostname.value)
        self.assertEqual(hostname_added[0]["value"], hostname.value)

    def test_ip(self):
        ip = Ip(value="1.1.1.1").save()
        ip_added = self.yeti_client.observable_search(value=ip.value)
        self.assertEqual(ip_added[0]["value"], ip.value)

    def test_email(self):
        email = Email(value="test@test.com").save()
        email_added = self.yeti_client.observable_search(value=email.value)
        self.assertEqual(email_added[0]["value"], email.value)

    def test_mac_address(self):
        mac_address = MacAddress(value="00:00:00:00:00:00").save()
        mac_address_added = self.yeti_client.observable_search(value=mac_address.value)
        self.assertEqual(mac_address_added[0]["value"], mac_address.value)

    def test_hash(self):
        hash = Hash(
            value="08be2c7239acb9557454088bba877a245c8ef9b0e9eb389c65a98e1c752c5709"
        ).save()
        hash_added = self.yeti_client.observable_search(value=hash.value)
        self.assertEqual(hash_added[0]["value"], hash.value)

    def test_url(self):
        url = Url(value="http://www.test.com").save()
        url_added = self.yeti_client.observable_search(value=url.value)
        self.assertEqual(url_added[0]["value"], url.value)

    def test_text(self):
        text = Text(value="test").save()
        text_added = self.yeti_client.observable_search(value=text.value)
        self.assertEqual(text_added[0]["value"], text.value)

    def tearDown(self) -> None:
        self.db.drop_database("yeti")
        return super().tearDown()


if __name__ == "__main__":
    unittest.main()
