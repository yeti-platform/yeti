import datetime

from core import database_arango
from core.schemas.observable import Observable

import unittest

from core.web import webapp

class ObservableTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_observable_create(self) -> None:
        result = Observable(
            value="toto.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        self.assertEqual(result.value, "toto.com")

    def test_observable_find(self) -> None:
        result = Observable(
            value="toto.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        observable = Observable.find(value="toto.com")
        self.assertIsNotNone(observable)
        self.assertEqual(observable.value, "toto.com")  # type: ignore

        observable = Observable.find(value="tata.com")
        self.assertIsNone(observable)

    def test_observable_links(self) -> None:
        observable1 = Observable(
            value="toto.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()
        observable2 = Observable(
            value="tata.com",
            type="hostname",
            created=datetime.datetime.now(datetime.timezone.utc)).save()

        observable1.link_to(observable2, "test")
