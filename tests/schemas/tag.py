import unittest
from typing import Optional

from core import database_arango
from core.schemas.observable import Observable
from core.schemas.observables import hostname
from core.schemas.tag import Tag


class TagTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.clear()
        self.obs1 = hostname.Hostname(value="test1.com").save()
        self.obs2 = hostname.Hostname(value="test2.com").save()

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
        tags = obs.get_tags()
        self.assertEqual(len(tags), 1)
        tag_rel, tag_data = tags[0]
        self.assertEqual(tag_data.name, "test")
        self.assertEqual(tag_rel.fresh, True)

    def test_tags_must_be_saved(self) -> None:
        """Test that ObservableTags must be saved to the database."""
        unsaved = hostname.Hostname(value="test1.com")
        with self.assertRaises(RuntimeError) as error:
            unsaved.tag(["tag"])
        self.assertEqual(str(error.exception), 'Cannot tag unsaved object, make sure to save() it first.')

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

    def test_tag_input_type(self):
        """Test that tags input is of type list, set or tuple."""
        with self.assertRaises(ValueError) as error:
            self.obs1.tag("tag")
        self.assertEqual(str(error.exception), "Tags must be of type list, set or tuple.")

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
        tag_relationship, _ = tags[0]
        self.assertEqual(tag_relationship.fresh, False)

        self.obs1.tag(["test"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        tag_relationship, _ = tags[0]
        self.assertEqual(tag_relationship.fresh, True)

    def test_clear_tags(self) -> None:
        """Test that tags can be cleared from an observable."""
        self.obs1.tag(["test"])
        self.obs1.clear_tags()
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 0)

    def test_tag_strict(self) -> None:
        """Test that tags can be cleared from an observable."""
        self.obs1.tag(["test1", "test2", "test3"])
        self.obs1.tag(["test"], strict=True)
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)

    def test_tag_replaces(self) -> None:
        """Test that a tag can replace another tag."""
        tag: Optional[Tag] = Tag(name="testst").save()
        newtag = Tag(name="test").save()
        newtag.replaces = ["testst"]
        newtag = newtag.save()

        self.obs1.tag(["testst"])
        tags = self.obs1.get_tags()
        self.assertEqual(len(tags), 1)
        tag_rel, tag_data = tags[0]
        self.assertEqual(tag_data.name, "test")

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
        tag_names = [tag[1].name for tag in tags]
        self.assertEqual(sorted(tag_names), sorted(["test", "test_extended"]))

        tag = Tag.find(name="test_extended")
        assert tag is not None
        self.assertEqual(tag.count, 1)
        tag = Tag.find(name="test")
        assert tag is not None
        self.assertEqual(tag.count, 1)

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
            ("type:some-custom-type", "type:some-custom-type")
        ]

        for cmp, (tag_non_norm, tag_norm) in enumerate(cases):
            obs = Observable.add_text(f"test_{cmp}.com")
            obs.tag([tag_non_norm])
            self.assertIn(tag_norm, obs.tags)
