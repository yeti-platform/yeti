import datetime

from typing import Optional

from core import database_arango
from core.schemas.observable import Observable
from core.schemas.tag import Tag

import unittest

class TagTest(unittest.TestCase):

    def setUp(self) -> None:
        database_arango.db.clear()
        self.obs1 = Observable(value="test1.com", type="hostname").save()
        self.obs2 = Observable(value="test2.com", type="hostname").save()

    def tearDown(self) -> None:
        database_arango.db.clear()

    def test_tag_create(self) -> None:
        """Test that a tag can be created"""
        tag = Tag(name="test").save()
        self.assertEqual(tag.name, "test")
        self.assertIsNotNone(tag.id)

    def test_tags_persist(self) -> None:
        """Test that ObservableTags persist in the database."""
        self.obs1.tag(["test"])
        obs = Observable.find(value="test1.com")
        assert obs is not None
        self.assertEqual(len(obs.tags), 1)
        self.assertEqual(obs.tags["test"].name, "test")

    def test_tag_updates_count(self) -> None:
        """Test that the count of a tag is updated when a tag is added
        to an observable."""
        tag = Tag(name="test").save()
        self.assertEqual(tag.count, 0)
        self.obs1.tag(["test"])
        fresh_tag = Tag.find(name="test")
        assert fresh_tag is not None
        self.assertEqual(fresh_tag.count, 1)

    def test_tag_is_created(self) -> None:
        """Test that a tag is created when it is added to an observable."""
        self.obs1.tag(["test"])
        tags = list(Tag.list())
        self.assertEqual(len(list(tags)), 1)
        self.assertEqual(tags[0].name, "test")

    def test_tag_replaces(self) -> None:
        """Test that a tag can replace another tag."""
        tag: Optional[Tag] = Tag(name="testst").save()
        newtag = Tag(name="test").save()
        newtag.replaces = ["testst"]
        newtag = newtag.save()

        self.obs1.tag(["testst"])
        self.assertEqual(len(self.obs1.tags), 1)
        self.assertEqual(self.obs1.tags["test"].name, "test")

        tag = Tag.find(name="testst")
        assert tag is not None
        self.assertEqual(tag.count, 0)
        tag = Tag.find(name="test")
        assert tag is not None
        self.assertEqual(tag.count, 1)

    def test_tag_produces(self) -> None:
        """Test that a tag can produce another tag."""
        Tag(name="test", produces=["test_extended"]).save()

        self.obs1.tag(["test"])
        self.assertEqual(len(self.obs1.tags), 2)
        self.assertEqual(self.obs1.tags["test"].name, "test")
        self.assertEqual(self.obs1.tags["test_extended"].name, "test_extended")

        tag = Tag.find(name="test_extended")
        assert tag is not None
        self.assertEqual(tag.count, 1)
        tag = Tag.find(name="test")
        assert tag is not None
        self.assertEqual(tag.count, 1)

    def test_tag_absorb_permanent(self) -> None:
        """Test that a tag can absorb another tag."""
        tag = Tag(name="test").save()
        Tag(name="old_tag_1",
            produces=["tag_prod1"],
            count=10).save()
        Tag(name="old_tag_2",
            replaces=["typod_tag"],
            produces=["tag_prod2"]).save()
        merge_count = tag.absorb(
            ["old_tag_1", "old_tag_2"], permanent=True)

        self.assertEqual(merge_count, 2)
        self.assertEqual(tag.count, 10)
        self.assertEqual(
            sorted(tag.replaces),
            sorted(['old_tag_1', 'old_tag_2', 'typod_tag']))
        self.assertEqual(
            sorted(tag.produces),
            sorted(['tag_prod1', 'tag_prod2']))

        self.assertIsNone(Tag.find(name="old_tag_1"))
        self.assertIsNone(Tag.find(name="old_tag_1"))
        self.assertIsNotNone(Tag.find(name="test"))

    def test_tag_absorb_non_permanent(self) -> None:
        """Test that a tag can absorb another tag."""
        tag = Tag(name="test").save()
        Tag(name="old_tag_1",
            produces=["tag_prod1"],
            count=10).save()
        Tag(name="old_tag_2",
            replaces=["typod_tag"],
            produces=["tag_prod2"]).save()

        merge_count = tag.absorb(
            ["old_tag_1", "old_tag_2"], permanent=False)

        self.assertEqual(merge_count, 2)
        self.assertEqual(tag.replaces, [])
        self.assertEqual(tag.produces, [])
        self.assertEqual(tag.count, 10)

        self.assertIsNotNone(Tag.find(name="old_tag_1"))
        self.assertIsNotNone(Tag.find(name="old_tag_2"))
        self.assertIsNotNone(Tag.find(name="test"))

        tag2 = Tag.find(name="old_tag_1")
        assert tag2 is not None
        self.assertEqual(tag2.count, 0)