import datetime

from core import database_arango
from core.schemas.observable import Observable
from core.schemas.entity import Actor, Entity
from core.schemas.graph import Relationship

import unittest

class EntityTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_create_entity(self) -> None:
        result = Actor(name="APT0").save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "APT0")
        self.assertEqual(result.type, "actor")

    def test_entity_with_tags(self):
        entity = Actor(name="APT0", relevant_tags=["tag1", "tag2"]).save()
        observable = Observable(
            value='doman.com',
            type='hostname').save()

        observable.tag(["tag1"])
        neighbors = observable.neighbors()

        self.assertEqual(len(neighbors.vertices), 1)
        self.assertEqual(neighbors.vertices[entity.extended_id].json(), entity.json())
