import datetime
import unittest
from typing import Optional

from core import database_arango
from core.schemas import observable
from core.schemas.observables import hostname
from core.schemas.tag import Tag


class TagTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()
        self.obs1 = hostname.Hostname(value="test1.com").save()
        self.obs2 = hostname.Hostname(value="test2.com").save()

    def test_tag_create(self) -> None:
        """Test that a tag can be created"""
        tag = Tag(name="test").save()
        self.assertEqual(tag.name, "test")
        self.assertIsNotNone(tag.id)

    def test_tags_persist(self) -> None:
        """Test that ObservableTags persist in the database."""
        self.obs1.tag(["test"])
        self.obs1.save()
        obs = observable.find(value="test1.com")
        assert obs is not None
        self.assertEqual(len(obs.tags), 1)

        self.assertEqual(obs.tags[0].name, "test")
        self.assertEqual(obs.tags[0].fresh, True)

    def test_tag_updates_count(self) -> None:
        """Test that the count of a tag is updated when a tag is added
        to an observable."""
        tag = Tag(name="test").save()
        tag = Tag(name="test2").save()
        self.assertEqual(tag.count, 0)
        self.obs1.tag(["test", "test2"])
        fresh_tag = Tag.find(name="test")
        self.assertEqual(fresh_tag.count, 1)
        fresh_tag = Tag.find(name="test2")
        self.assertEqual(fresh_tag.count, 1)

    def test_tag_is_created(self) -> None:
        """Test that a tag is created when it is added to an observable."""
        self.obs1.tag(["test"])
        tags = list(Tag.list())
        self.assertEqual(len(list(tags)), 1)
        self.assertEqual(tags[0].name, "test")

    def test_tag_input_type(self):
        """Test that tags input is of type list, set or tuple."""
        with self.assertRaises(ValueError) as error:
            self.obs1.tag("tag")
        self.assertEqual(
            str(error.exception), "Tags must be of type list, set or tuple."
        )

    def test_tag_is_overwritten(self) -> None:
        """Test that a tag is overwritten when it is added to an observable."""
        self.obs1.tag(["test"])
        self.obs1.tag(["test"])
        tags = list(Tag.list())
        self.assertEqual(len(list(tags)), 1)
        self.assertEqual(tags[0].name, "test")

    def test_tag_expiration(self) -> None:
        """Test that a tag can be expired and it becomes fresh if tagged again."""
        self.obs1.tag(["test"])
        self.obs1.expire_tag("test")
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        tag_instance = tags["test"]
        self.assertEqual(tag_instance.fresh, False)

        self.obs1.tag(["test"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        tag_instance = tags["test"]
        self.assertEqual(tag_instance.fresh, True)

    def test_tag_manual_expiration_date(self) -> None:
        """Test that a tag's expiration date takes in the manualy specified value."""
        self.obs1.tag(["test"], expiration=datetime.timedelta(minutes=5))
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        tag_instance = tags["test"]
        self.assertIsNotNone(tag_instance.expires)
        self.assertGreater(
            tag_instance.expires,
            tag_instance.last_seen + datetime.timedelta(minutes=2),
        )
        self.assertLess(
            tag_instance.expires,
            tag_instance.last_seen + datetime.timedelta(minutes=6),
        )

    def test_default_tag_expiration(self) -> None:
        """Test that a tag's expiration date tages the tag's default."""
        Tag(name="test", default_expiration=datetime.timedelta(days=365)).save()
        self.obs1.tag(["test"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        tag_relationship = tags["test"]
        self.assertIsNotNone(tag_relationship.expires)
        self.assertGreater(
            tag_relationship.expires,
            tag_relationship.last_seen + datetime.timedelta(days=364),
        )
        self.assertLess(
            tag_relationship.expires,
            tag_relationship.last_seen + datetime.timedelta(days=366),
        )

    def test_clear_tags(self) -> None:
        """Test that tags can be cleared from an observable."""
        self.obs1.tag(["test"])
        self.obs1.clear_tags()
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 0)

    def test_tag_strict(self) -> None:
        """Test that tags can be cleared from an observable."""
        self.obs1.tag(["test1", "test2", "test3"])
        self.obs1.tag(["test"], clear=True)
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)

    def test_tag_replaces(self) -> None:
        """Test that a tag can replace another tag."""
        tag = Tag(name="testst").save()
        newtag = Tag(name="test").save()
        newtag.replaces = ["testst"]
        newtag = newtag.save()

        self.obs1.tag(["testst"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        self.assertEqual(tags["test"].name, "test")

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
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 2)
        tag_names = [tag.name for tag in tags.values()]
        self.assertEqual(sorted(tag_names), sorted(["test", "test_extended"]))

        tag = Tag.find(name="test_extended")
        assert tag is not None
        self.assertEqual(tag.count, 1)
        tag = Tag.find(name="test")
        assert tag is not None
        self.assertEqual(tag.count, 1)

    def test_tag_recursion_loop(self) -> None:
        """Test that a tag can produce multiple tags."""
        Tag(name="test1", produces=["test2"]).save()
        Tag(name="test2", produces=["test3"]).save()
        Tag(name="test3", produces=["test1"]).save()

        self.obs1.tag(["test1"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 3)
        tag_names = [tag.name for tag in tags.values()]
        self.assertEqual(sorted(tag_names), sorted(["test1", "test2", "test3"]))

    def test_tag_absorb_permanent(self) -> None:
        """Test that a tag can absorb another tag."""
        tag = Tag(name="test").save()
        Tag(name="old_tag_1", produces=["tag_prod1"], count=10).save()
        Tag(name="old_tag_2", replaces=["typod_tag"], produces=["tag_prod2"]).save()
        merge_count = tag.absorb(["old_tag_1", "old_tag_2"], permanent=True)

        self.assertEqual(merge_count, 2)
        self.assertEqual(tag.count, 10)
        self.assertEqual(
            sorted(tag.replaces), sorted(["old_tag_1", "old_tag_2", "typod_tag"])
        )
        self.assertEqual(sorted(tag.produces), sorted(["tag_prod1", "tag_prod2"]))

        self.assertIsNone(Tag.find(name="old_tag_1"))
        self.assertIsNone(Tag.find(name="old_tag_1"))
        self.assertIsNotNone(Tag.find(name="test"))

    def test_tag_absorb_non_permanent(self) -> None:
        """Test that a tag can absorb another tag."""
        tag = Tag(name="test").save()
        Tag(name="old_tag_1", produces=["tag_prod1"], count=10).save()
        Tag(name="old_tag_2", replaces=["typod_tag"], produces=["tag_prod2"]).save()

        merge_count = tag.absorb(["old_tag_1", "old_tag_2"], permanent=False)

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

    def test_duplicate_name(self):
        """Tests that a saving a tag with the same name will return the existing tag."""
        tag = Tag(name="test").save()
        tag2 = Tag(name="test").save()
        self.assertEqual(tag.id, tag2.id)

    def test_normalized_tag(self):
        """Tests that a tag can be normalized."""
        cases = [
            ("H@ackërS T3st", "hackers_t3st"),
            ("    SpaCesStartEnd  ", "spacesstartend"),
            ("!!Sp3cial##", "sp3cial"),
            ("Multi    Spaces   After", "multi_spaces_after"),
            ("Élévation", "elevation"),
            ("UNDER_score", "under_score"),
            ("mixCaseMix123", "mixcasemix123"),
            ("MïxedÁccénts", "mixedaccents"),
            ("123456", "123456"),
            ("测试chinese", "chinese"),
            ("type:some-custom-type", "type:some-custom-type"),
        ]

        for cmp, (tag_non_norm, tag_norm) in enumerate(cases):
            obs = observable.save(value=f"test-{cmp}.com")
            obs.tag([tag_non_norm])
            self.assertIn(tag_norm, {tag.name for tag in obs.tags})
